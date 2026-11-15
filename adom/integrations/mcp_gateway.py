#!/usr/bin/env python3
"""ADOM MCP gateway: put ADOM in front of any stdio MCP server (v1, 2026-10-25).

    python3 -m adom.integrations.mcp_gateway --name notes -- python3 notes_server.py

The gateway is the MCP server the client talks to. It starts the real server as a child
process and relays JSON-RPC messages both ways, line by line (MCP stdio transport). Every
`tools/call` is decided by ADOM before the real server sees it:

  * the tool's name is namespaced like Claude Code does it: mcp__<name>__<tool>
  * adom.enforcement.action_tiers classifies it (operator registry ~/.adom/tool_tiers.json,
    plus the server's own annotations from tools/list, which can only RAISE a tier)
  * unknown tools are denied; credential paths in any argument are denied; credential-shaped
    values in consequential arguments are denied
  * registry-granted tools are screened by ADOM's kernel (action_kernel.screen_action) with an
    exact grant for that one tool and the entry's approved_outbound hosts; a kernel block wins
  * a denied call never reaches the server: the client gets an MCP tool error
    ({"isError": true}) that says why, so the agent can carry on

Tool RESULTS of permitted calls are fed back to ADOM (note_read) so a value the agent read
through one tool is recognised if it later tries to send it through another (taint), and a
session that read sensitive or untrusted content cannot send to unapproved destinations.

Every decision is appended to a SHA-256 hash chain at ~/.adom/mcp/<name>.jsonl (the same
record format as the coding-agent hooks; `cursor_hook/watch.py`'s chain checker reads it).

What it does NOT do:
  * It only sees what goes through it. A client that also reaches the server another way,
    or a server that acts on its own, is outside its view.
  * It cannot confirm that a person sees an approval prompt in the client, so registry
    entries with "agent_approval": true are honoured only if the operator starts the
    gateway with --client-prompts-confirmed (an operator statement, logged on every call).
  * Streamable-HTTP / SSE MCP transports are not supported in v1 (stdio only).
  * Batched JSON-RPC arrays are split; any tools/call inside one is decided individually.
  * The audit chain is unkeyed unless --audit-key-file is given. Unkeyed, it shows a record
    edited or removed from the middle but not a fully rewritten log. Keyed, a writer without
    the key cannot rewrite it. Either way a truncated tail shows only against a pinned head:
    keep COUNT:HASH somewhere else and run `mcp_gateway verify LOG --head COUNT:HASH`.

Modes: --mode enforce (default) blocks; --mode observe forwards everything and logs what
ADOM would have done. Python 3.9+; standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adom.enforcement import action_tiers as tiers  # noqa: E402

MAX_LINE = 4 * 1024 * 1024            # a single JSON-RPC message larger than this is refused
MAX_OBSERVE = 256 * 1024              # bytes of a tool result fed to taint learning
_REVIEW_ONLY = {"toolcall:outbound:review", "action_kernel:review_required"}


# ----------------------------------------------------------------------------- audit log
# The chain lives in adom.enforcement.audit_chain (same record format). Unkeyed by default;
# pass --audit-key-file (or ADOM_AUDIT_KEY_FILE) for a keyed chain that a writer without the
# key cannot rewrite, and `verify --head COUNT:HASH` to detect a truncated tail.
from adom.enforcement.audit_chain import ChainLog, verify_chain, load_key  # noqa: E402,F401


# ----------------------------------------------------------------------------- decisions
def _result_text(result: Any) -> str:
    """Text an agent would read from an MCP tool, resource, or prompt result."""
    parts: List[str] = []
    def _collect_content(item: Any) -> None:
        if isinstance(item, dict):
            if item.get("type") == "text" and isinstance(item.get("text"), str):
                parts.append(item["text"])
            elif item.get("type") == "resource":
                res = item.get("resource") or {}
                if isinstance(res, dict) and isinstance(res.get("text"), str):
                    parts.append(res["text"])
            elif isinstance(item.get("text"), str) and "type" not in item:
                parts.append(item["text"])

    if isinstance(result, dict):
        for c in result.get("content") or []:
            _collect_content(c)
        for item in result.get("contents") or []:
            _collect_content(item)
        for msg in result.get("messages") or []:
            if isinstance(msg, dict):
                mc = msg.get("content")
                if isinstance(mc, list):
                    for part in mc:
                        _collect_content(part)
                else:
                    _collect_content(mc)
        if result.get("structuredContent") is not None:
            try:
                parts.append(json.dumps(result["structuredContent"], sort_keys=True))
            except (TypeError, ValueError):
                pass
    return "\n".join(parts)[:MAX_OBSERVE]


class Decider:
    """Per-gateway decision state. One long-lived kernel policy per granted tool keeps that
    tool's session state (taint, sensitive/untrusted reads, chunked-outbound accumulation);
    every permitted result is observed by all of them."""

    def __init__(self, server: str, registry_path: Optional[Path], client_prompts_confirmed: bool,
                 contracts: Any = None, approvals: Any = None):
        self.server = server
        self.contracts = contracts          # ContractRegistry keyed by mcp__<name>__<tool>
        self.approvals = approvals          # ApprovalStore; releases review-required only
        self.registry_path = registry_path
        self.client_prompts_confirmed = client_prompts_confirmed
        self.hints: Dict[str, Dict[str, Any]] = {}
        self._policies: Dict[str, Any] = {}
        self._observed: List[Tuple[str, str]] = []      # (path label, text) replayed into new policies
        self._lock = threading.Lock()
        self.poisoned = ""                              # non-empty: every later call is denied

    def qualified(self, tool: str) -> str:
        return f"mcp__{self.server}__{tool}"

    def learn_hints(self, tools: Any) -> None:
        if not isinstance(tools, list):
            return
        with self._lock:
            for t in tools:
                if isinstance(t, dict) and isinstance(t.get("name"), str):
                    ann = t.get("annotations")
                    self.hints[t["name"]] = dict(ann) if isinstance(ann, dict) else {}

    def _policy_for(self, name: str, entry: Any):
        from adom.api.model_proxy import ModelProxyPolicy
        key = (name, entry.tier, tuple(entry.approved_outbound))
        p = self._policies.get(key)
        if p is None:
            kwargs: Dict[str, Any] = dict(
                strict_deny_unknown=True,
                block_mode=True,
                track_session=True,
                allowed_tools=(name,),
                approved_outbound=list(entry.approved_outbound),
            )
            if "declared_kinds" in getattr(ModelProxyPolicy, "__dataclass_fields__", {}):
                kinds = {}
                if self.contracts is not None and self.contracts.get(name) is not None:
                    kinds = {name: self.contracts.get(name).kind}
                kwargs["declared_kinds"] = kinds
            p = ModelProxyPolicy(**kwargs)
            for label, text in self._observed:          # catch up on what was already read
                p.note_read(text, path=label, untrusted=True)
            p.seal()
            self._policies[key] = p
        return p

    def decide(self, tool: str, args: Any) -> Dict[str, Any]:
        name = self.qualified(tool)
        registry = tiers.load_registry(self.registry_path)
        with self._lock:
            hints = dict(self.hints.get(tool, {}))
        c = tiers.classify(name, args if isinstance(args, dict) else {}, agent="mcp",
                           hints=hints, registry=registry)
        td = tiers.decide(c)
        rec: Dict[str, Any] = dict(c.as_log(), tool=name, tier_decision=td.action)
        if hints:
            rec["hints"] = hints
        if self.poisoned:
            return dict(rec, verdict="block", reason=self.poisoned, signals=["mcp:session_poisoned"])
        if td.action == tiers.BLOCK:
            return dict(rec, verdict="block", reason=td.reason, signals=list(td.signals))
        if td.action != tiers.SCREEN:                  # MCP tools are never built-ins
            return dict(rec, verdict="block", reason="MCP tool without a registry grant",
                        signals=["mcp:not_granted"])
        from adom.api.model_proxy import ProxyVerdict
        from adom.enforcement.action_kernel import screen_action
        with self._lock:
            policy = self._policy_for(name, c.registry_entry)
            frozen, v = screen_action(policy, name, args if args is not None else {})
        if v.action == "flag":
            v = ProxyVerdict(
                action="block",
                reason="Exact trusted approval required; flag is not execution authority",
                signals=list(v.signals) + ["action_kernel:review_required"],
            )
        rec["kernel_action"] = v.action
        if self.contracts is not None or self.approvals is not None:
            from adom.enforcement.review import resolve
            v, _, digest = resolve(name, frozen, v, contracts=self.contracts,
                                   approvals=self.approvals, agent_id="mcp:" + self.server)
            rec["action_digest"] = digest
        sig = list(v.signals)
        if v.action == "allow":
            return dict(rec, verdict="allow", reason=v.reason if "approval:exact:consumed" in sig else "",
                        signals=sig)
        e = c.registry_entry
        review_only = "action_kernel:review_required" in sig and \
            set(sig) <= _REVIEW_ONLY | {"approval:pending", "approval:queue_unavailable"}
        if e is not None and e.agent_approval and review_only:
            if self.client_prompts_confirmed:
                return dict(rec, verdict="allow", signals=sig + ["mcp:client_prompt_operator_confirmed"],
                            reason="kernel review delegated to the client's approval prompt "
                                   "(registry opt-in; operator confirmed prompts are shown)")
            return dict(rec, verdict="block", signals=sig + ["tier:agent_approval_unconfirmed"],
                        reason=f"{v.reason}; agent_approval not honored: the gateway cannot "
                               f"confirm the client shows an approval prompt "
                               f"(start it with --client-prompts-confirmed if it does)")
        return dict(rec, verdict="block", reason=v.reason or "kernel denied", signals=sig)

    def observe(self, tool: str, result: Any) -> None:
        text = _result_text(result)
        if not text:
            return
        label = f"mcp:{self.server}/{tool}"
        with self._lock:
            self._observed.append((label, text))
            if len(self._observed) > 512:
                self._observed = self._observed[-512:]
            for p in self._policies.values():
                p.note_read(text, path=label, untrusted=True)


# ----------------------------------------------------------------------------- relay
class Gateway:
    def __init__(self, server_cmd: List[str], name: str, mode: str = "enforce",
                 registry_path: Optional[Path] = None, log_path: Optional[Path] = None,
                 client_prompts_confirmed: bool = False,
                 stdin=None, stdout=None, audit_key: Optional[bytes] = None,
                 contracts: Any = None, approvals: Any = None,
                 anchor_path: Optional[Path] = None):
        self.name = name
        self.mode = mode
        self.decider = Decider(name, registry_path, client_prompts_confirmed,
                               contracts=contracts, approvals=approvals)
        eff_anchor = anchor_path or (Path(os.environ["ADOM_AUDIT_ANCHOR_PATH"])
                                     if os.environ.get("ADOM_AUDIT_ANCHOR_PATH") else None)
        self.log = ChainLog(log_path or Path.home() / ".adom" / "mcp" / f"{name}.jsonl",
                            key=audit_key, anchor_path=eff_anchor)
        self.client_in = stdin or sys.stdin.buffer
        self.client_out = stdout or sys.stdout.buffer
        self.server_cmd = server_cmd
        self._out_lock = threading.Lock()
        self._pending: Dict[Any, Tuple[str, Optional[str]]] = {}   # id -> (method, tool)
        self._plock = threading.Lock()
        self.proc: Optional[subprocess.Popen] = None

    # -- io helpers
    def _to_client(self, obj: Any) -> None:
        data = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
        with self._out_lock:
            self.client_out.write(data)
            self.client_out.flush()

    def _to_server(self, obj: Any) -> None:
        assert self.proc is not None and self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(obj, separators=(",", ":")) + "\n").encode())
        self.proc.stdin.flush()

    def _record(self, rec: Dict[str, Any]) -> bool:
        try:
            self.log.append(rec)
            return True
        except Exception:
            return False

    @staticmethod
    def _tool_error(msg_id: Any, text: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id,
                "result": {"content": [{"type": "text", "text": text}], "isError": True}}

    @staticmethod
    def _rpc_error(msg_id: Any, code: int, text: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": text}}

    def _screen_auxiliary(self, method: str, params: Dict[str, Any]) -> Tuple[bool, str, List[str], str]:
        """Screen resources/read and prompts/get against credential/persistence/secret policy."""
        if method == "resources/read":
            uri = params.get("uri")
            if not isinstance(uri, str) or not uri.strip():
                return False, "resources/read without a valid URI", ["mcp:malformed_resource_read"], ""
            target = uri[7:] if uri.lower().startswith("file://") else uri
            cred = tiers.credential_label(target)
            if cred:
                return False, f"credential containment: resources/read blocked ({cred})", ["tier:credential_store"], uri[:300]
            if tiers._DOTENV_RX.search(target.lower()) and not tiers._DOTENV_SAFE_RX.search(target.lower()):
                return False, "credential containment: resources/read blocked (.env)", ["tier:credential_store", "tier:dotenv"], uri[:300]
            secs = tiers.secret_labels([uri])
            if secs:
                return False, f"resources/read carries a credential-shaped value ({', '.join(secs)})", ["tier:secret_in_outbound_args"], uri[:300]
            return True, "", [], uri[:300]
        if method == "prompts/get":
            pname = str(params.get("name") or "")
            pargs = params.get("arguments") or {}
            secs = tiers.secret_labels(tiers.strings(pargs))
            if secs:
                return False, f"prompts/get carries a credential-shaped value ({', '.join(secs)})", ["tier:secret_in_outbound_args"], pname[:300]
            for path in tiers.paths_in(pargs, everywhere=True):
                cred = tiers.credential_label(path)
                if cred:
                    return False, f"credential containment: prompts/get blocked ({cred})", ["tier:credential_store"], pname[:300]
            return True, "", [], pname[:300]
        return True, "", [], ""

    # -- client -> server
    def _handle_client_message(self, msg: Any) -> Optional[Any]:
        """Return the message to forward to the server, or None if answered here."""
        if not isinstance(msg, dict):
            return msg
        method, msg_id = msg.get("method"), msg.get("id")
        if method == "tools/list" and msg_id is not None:
            with self._plock:
                self._pending[msg_id] = ("tools/list", None)
            return msg
        if method in ("resources/read", "prompts/get"):
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            ok, why, sigs, subj = self._screen_auxiliary(method, params)
            forward = ok or self.mode == "observe"
            rec = {"ts": time.time(), "agent": "mcp_gateway", "server": self.name,
                   "event": method, "mode": self.mode,
                   "adom_verdict": "allow" if ok else "block", "reason": why,
                   "signals": sigs, "subject": subj,
                   "returned": "forwarded" if forward else "denied"}
            logged = self._record(rec)
            if forward and not logged and self.mode == "enforce":
                forward, why = False, "ADOM audit log unavailable"
            if not forward:
                if msg_id is not None:
                    self._to_client(self._rpc_error(msg_id, -32001, "ADOM blocked " + method + ": " + why))
                return None
            if msg_id is not None:
                with self._plock:
                    self._pending[msg_id] = (method, subj or method)
            return msg
        if method != "tools/call":
            return msg
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        tool = params.get("name")
        args = params.get("arguments", {})
        started = time.perf_counter()
        if not isinstance(tool, str) or not tool:
            d = {"verdict": "block", "reason": "tools/call without a tool name",
                 "signals": ["mcp:malformed_call"], "tool": None}
        else:
            try:
                d = self.decider.decide(tool, args)
            except Exception as exc:                    # fail closed on any internal error
                d = {"verdict": "block", "reason": f"ADOM gateway error: {type(exc).__name__}",
                     "signals": ["mcp:gateway_error_fail_closed"], "tool": self.decider.qualified(tool)}
        forward = d["verdict"] == "allow" or self.mode == "observe"
        rec = dict(d, ts=time.time(), agent="mcp_gateway", server=self.name, event="tools/call",
                   mode=self.mode, adom_verdict=d["verdict"], subject=str(tool)[:300],
                   returned="forwarded" if forward else "denied",
                   latency_ms=round((time.perf_counter() - started) * 1000, 2))
        if self.decider.client_prompts_confirmed:
            rec["operator_statement"] = "client approval prompts confirmed by operator"
        logged = self._record(rec)
        if forward and not logged and self.mode == "enforce":
            forward, d = False, dict(d, reason="ADOM audit log unavailable")
        if not forward:
            if msg_id is not None:
                self._to_client(self._tool_error(msg_id, "ADOM blocked this tool call: " + d["reason"]))
            return None
        if msg_id is not None:
            with self._plock:
                self._pending[msg_id] = ("tools/call", tool)
        return msg

    def _client_pump(self) -> None:
        try:
            for raw in iter(self.client_in.readline, b""):
                if not raw.strip():
                    continue
                if len(raw) > MAX_LINE:
                    self._record({"ts": time.time(), "agent": "mcp_gateway", "server": self.name,
                                  "event": "oversize_message", "adom_verdict": "block"})
                    continue
                try:
                    msg = json.loads(raw)
                except ValueError:
                    self._to_client({"jsonrpc": "2.0", "id": None,
                                     "error": {"code": -32700, "message": "Parse error"}})
                    continue
                if isinstance(msg, list):               # batch: decide each element
                    out = [m for m in (self._handle_client_message(x) for x in msg) if m is not None]
                    if out:
                        self._to_server(out)
                    continue
                fwd = self._handle_client_message(msg)
                if fwd is not None:
                    self._to_server(fwd)
        except (BrokenPipeError, ValueError, OSError):
            pass
        finally:
            try:
                if self.proc and self.proc.stdin:
                    self.proc.stdin.close()
            except OSError:
                pass

    # -- server -> client
    def _handle_server_message(self, msg: Any) -> Any:
        if not isinstance(msg, dict):
            return msg
        # Server-initiated notifications & requests (e.g. tools/list_changed, sampling, elicitation)
        if "method" in msg:
            smethod = msg.get("method")
            if smethod == "notifications/tools/list_changed":
                with self.decider._lock:
                    self.decider.hints.clear()
                self._record({"ts": time.time(), "agent": "mcp_gateway", "server": self.name,
                              "event": "tools_list_changed", "mode": self.mode,
                              "adom_verdict": "flag", "signals": ["mcp:tools_list_changed"]})
                return msg
            if "id" in msg and smethod in ("sampling/createMessage", "elicitation/create"):
                allow = self.mode != "enforce"
                self._record({"ts": time.time(), "agent": "mcp_gateway", "server": self.name,
                              "event": "server_request:" + str(smethod), "mode": self.mode,
                              "adom_verdict": "block",
                              "returned": "forwarded" if allow else "denied",
                              "signals": ["mcp:server_initiated_request_blocked"]})
                if not allow:
                    self._to_server(self._rpc_error(
                        msg["id"], -32601, f"ADOM blocked server-initiated {smethod}"))
                    return None
            return msg
        if "id" not in msg:
            return msg
        with self._plock:
            pending = self._pending.pop(msg.get("id"), None)
        if not pending:
            return msg
        kind, tool = pending
        result = msg.get("result")
        if kind == "tools/list" and isinstance(result, dict):
            self.decider.learn_hints(result.get("tools"))
        elif kind in ("tools/call", "resources/read", "prompts/get") and tool and isinstance(result, dict):
            try:
                obs = result
                if kind == "resources/read" and isinstance(result.get("contents"), list):
                    # Convert MCP ReadResourceResult.contents[] into standard text parts for observe()
                    parts = []
                    for item in result["contents"]:
                        if isinstance(item, dict) and isinstance(item.get("text"), str):
                            parts.append({"type": "text", "text": item["text"]})
                    obs = {"content": parts}
                elif kind == "prompts/get" and isinstance(result.get("messages"), list):
                    parts = []
                    for item in result["messages"]:
                        c = item.get("content") if isinstance(item, dict) else None
                        if isinstance(c, dict) and isinstance(c.get("text"), str):
                            parts.append({"type": "text", "text": c["text"]})
                        elif isinstance(c, str):
                            parts.append({"type": "text", "text": c})
                    obs = {"content": parts}
                self.decider.observe(tool if kind == "tools/call" else f"{kind}:{tool}", obs)
            except Exception:
                # Could not learn from what the agent just read: later outbound decisions
                # would be blind to it, so poison the session rather than continue silently.
                self._record({"ts": time.time(), "agent": "mcp_gateway", "server": self.name,
                              "event": "observe_failed", "tool": self.decider.qualified(tool)})
                self.decider.poisoned = ("ADOM could not inspect an earlier tool result, so it "
                                         "cannot rule out that this call carries it; session closed")
        return msg

    def _server_pump(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        for raw in iter(self.proc.stdout.readline, b""):
            if not raw.strip():
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                continue                                # a server must not write junk on stdout
            if isinstance(msg, list):
                out = [m for m in (self._handle_server_message(x) for x in msg) if m is not None]
                if not out:
                    continue
                msg = out
            else:
                msg = self._handle_server_message(msg)
                if msg is None:
                    continue
            self._to_client(msg)
        # server exited: fail every request still waiting
        with self._plock:
            waiting, self._pending = list(self._pending), {}
        for msg_id in waiting:
            self._to_client({"jsonrpc": "2.0", "id": msg_id,
                             "error": {"code": -32603, "message": "upstream MCP server exited"}})

    def run(self) -> int:
        self._record({"ts": time.time(), "agent": "mcp_gateway", "server": self.name,
                      "event": "start", "mode": self.mode, "command": self.server_cmd[:1]})
        self.proc = subprocess.Popen(self.server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=sys.stderr)
        t_srv = threading.Thread(target=self._server_pump, daemon=True)
        t_srv.start()
        self._client_pump()
        t_srv.join(timeout=10)
        try:
            return self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return 1


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["verify"]:
        vp = argparse.ArgumentParser(prog="mcp_gateway verify")
        vp.add_argument("log", type=Path)
        vp.add_argument("--audit-key-file", type=Path,
                        default=os.environ.get("ADOM_AUDIT_KEY_FILE") or None)
        vp.add_argument("--head", default=None, help="pinned COUNT:HASH to check against")
        vo = vp.parse_args(argv[1:])
        try:
            key = load_key(vo.audit_key_file)
            head = None
            if vo.head:
                count, _, want = vo.head.partition(":")
                head = (int(count), want)
        except (OSError, ValueError) as exc:
            print(f"BROKEN: {exc}")
            return 1
        ok, why = verify_chain(vo.log, key=key, expected_head=head)
        print(("OK: " if ok else "BROKEN: ") + why)
        return 0 if ok else 1
    if "--" not in argv:
        print("usage: mcp_gateway --name NAME [--mode enforce|observe] [--registry PATH] "
              "[--log PATH] [--audit-key-file PATH] [--contracts PATH] "
              "[--approvals-db PATH --approval-key-file PATH] [--client-prompts-confirmed] "
              "-- SERVER_COMMAND ...\n"
              "       mcp_gateway verify LOG_PATH [--audit-key-file PATH] [--head COUNT:HASH]",
              file=sys.stderr)
        return 2
    cut = argv.index("--")
    ap = argparse.ArgumentParser(prog="mcp_gateway")
    ap.add_argument("--name", required=True,
                    help="server name used in tool names (mcp__NAME__tool) and the log file")
    ap.add_argument("--mode", choices=("enforce", "observe"), default="enforce")
    ap.add_argument("--registry", type=Path, default=None)
    ap.add_argument("--log", type=Path, default=None)
    ap.add_argument("--client-prompts-confirmed", action="store_true")
    ap.add_argument("--audit-key-file", type=Path,
                    default=os.environ.get("ADOM_AUDIT_KEY_FILE") or None)
    ap.add_argument("--anchor-path", type=Path,
                    default=os.environ.get("ADOM_AUDIT_ANCHOR_PATH") or None,
                    help="external monotonic COUNT:HASH anchor file updated on every append")
    ap.add_argument("--contracts", type=Path, default=None,
                    help="tool contracts JSON, keyed by mcp__NAME__tool; tools without one are refused")
    ap.add_argument("--approvals-db", type=Path, default=None,
                    help="approval store; review-required calls wait here for a person")
    ap.add_argument("--approval-key-file", type=Path,
                    default=os.environ.get("ADOM_APPROVAL_KEY_FILE") or None)
    opts = ap.parse_args(argv[:cut])
    server_cmd = argv[cut + 1:]
    if not server_cmd:
        print("mcp_gateway: no server command after --", file=sys.stderr)
        return 2
    if not opts.name.replace("-", "").replace("_", "").isalnum():
        print("mcp_gateway: --name must be letters, digits, - or _", file=sys.stderr)
        return 2
    try:
        audit_key = load_key(opts.audit_key_file)
    except (OSError, ValueError) as exc:
        # A key was asked for and cannot be used: do not quietly fall back to an unkeyed log.
        print(f"mcp_gateway: audit key unusable: {exc}", file=sys.stderr)
        return 2
    contracts = approvals = None
    try:
        if opts.contracts is not None:
            from adom.enforcement.tool_contracts import ContractRegistry
            contracts = ContractRegistry.from_file(opts.contracts)
        if opts.approvals_db is not None:
            from adom.enforcement.approvals import ApprovalStore
            if opts.approval_key_file is None:
                raise ValueError("--approvals-db needs --approval-key-file")
            approvals = ApprovalStore(str(opts.approvals_db), key=load_key(opts.approval_key_file))
    except (OSError, ValueError) as exc:
        # Asked for and unusable: refuse to start rather than run without it.
        print(f"mcp_gateway: contracts/approvals unusable: {exc}", file=sys.stderr)
        return 2
    return Gateway(server_cmd, opts.name, opts.mode, opts.registry, opts.log,
                   opts.client_prompts_confirmed, audit_key=audit_key,
                   contracts=contracts, approvals=approvals,
                   anchor_path=opts.anchor_path).run()


if __name__ == "__main__":
    sys.exit(main())
