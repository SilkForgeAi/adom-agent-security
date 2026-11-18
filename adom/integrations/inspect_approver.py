"""ADOM Deterministic Approver & AI-Control Pre-Filter for UK AISI Inspect (`inspect_ai`).

Integrates ADOM's model-independent enforcement boundary (`ModelProxyPolicy`,
`action_kernel.screen_action`, `BlastRadiusController`, and SHA-256 `ChainLog`)
into UK AI Security Institute's `inspect_ai` `Approver` extension API:

1. **Stateful Cross-Turn Taint across `history: list[ChatMessage]`:**
   `inspect_ai`'s built-in `ApprovalPolicy` (`src/inspect_ai/approval/_policy.py`)
   performs stateless `fnmatch` glob checks on single-turn `ToolCall` names and
   named arguments. `adom_approver` ingests prior `ChatMessageTool` outputs from
   `history` into session taint state (`note_read`) so secrets or canaries read
   in Turn 1 cannot be exfiltrated raw or encoded (`base64`, `hex`, URL-encoded,
   reversed, chunked) in Turn 2+.

2. **AI-Control Pre-Filter (`mode="control_prefilter"`):**
   In `inspect_ai` (`src/inspect_ai/approval/_apply.py`), `apply_tool_approval`
   executes approvers inside `with suspend_limits():` so trusted LLM-monitor tokens
   and latency are exempt from sample limits. Placing `adom_approver(mode="control_prefilter")`
   ahead of an LLM/human monitor in `ApprovalPolicy`:
   - Deterministically rejects prohibited/tainted/SSRF calls in `<0.05 ms` `p50`
     at `$0` monitor inference cost (`decision="reject"`),
   - Terminates runaway untrusted-model retry loops via `BlastRadiusController`
     (`decision="terminate"`), halting sample execution before monitor spend balloons,
   - Returns `decision="escalate"` on schema- and taint-clean calls so Inspect's
     `PolicyApprover` hands off subtle semantic review to the downstream monitor.

3. **Exact Tool-Grant & `parse_error` Fail-Closed Semantics:**
   Closes `tool_call_matcher`'s prefix-glob expansion (`tools="read"` matching
   `read_secret_store`), missing-key argument fallthrough, and malformed JSON
   `ToolCall.parse_error` pass-through.

Zero external runtime dependencies: runs standalone on Python 3.10+ stdlib and
automatically registers with `@inspect_ai.approval.approver` when `inspect_ai` is installed.
"""
from __future__ import annotations

import collections
import hashlib
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from adom.api.model_proxy import ModelProxyPolicy, _collect_strings, _looks_external, _safe_label
from adom.enforcement import action_tiers as tiers
from adom.enforcement.action_kernel import screen_action
from adom.enforcement.audit_chain import ChainLog, load_key
from adom.enforcement.blast_radius import BlastRadiusController, Budget

try:
    from inspect_ai.approval import Approval as _InspectApproval  # type: ignore[import-not-found]
    from inspect_ai.approval import approver as _inspect_approver_decorator  # type: ignore[import-not-found]

    HAS_INSPECT_AI = True
except Exception:  # pragma: no cover - optional runtime integration
    _InspectApproval = None
    _inspect_approver_decorator = None
    HAS_INSPECT_AI = False

_MAX_SESSIONS = 1024
_MAX_OBSERVED_TOOL_BYTES = 262144


@dataclass
class AdomApprovalResult:
    """Stdlib drop-in matching `inspect_ai.approval.Approval` fields when `inspect_ai` is absent."""

    decision: str  # "approve" | "modify" | "reject" | "terminate" | "escalate"
    modified: Any = None
    explanation: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


def _make_approval(
    decision: str,
    explanation: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Any:
    if _InspectApproval is not None:
        return _InspectApproval(decision=decision, explanation=explanation, metadata=metadata)
    return AdomApprovalResult(decision=decision, explanation=explanation, metadata=metadata)


def _extract_message_text(msg: Any) -> str:
    """Extract plain text from an Inspect `ChatMessage` or dict equivalent."""
    if msg is None:
        return ""
    if isinstance(msg, dict):
        content = msg.get("content")
    else:
        txt_prop = getattr(msg, "text", None)
        if isinstance(txt_prop, str):
            return txt_prop[:_MAX_OBSERVED_TOOL_BYTES]
        content = getattr(msg, "content", None)

    if isinstance(content, str):
        return content[:_MAX_OBSERVED_TOOL_BYTES]
    if isinstance(content, list):
        parts: List[str] = []
        for item in content[:256]:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
            else:
                itxt = getattr(item, "text", None)
                if isinstance(itxt, str):
                    parts.append(itxt)
        return "\n".join(parts)[:_MAX_OBSERVED_TOOL_BYTES]
    return ""


def _msg_role(msg: Any) -> str:
    if isinstance(msg, dict):
        return str(msg.get("role") or "")
    return str(getattr(msg, "role", "") or "")


def _msg_id_or_digest(msg: Any, idx: int) -> str:
    mid = msg.get("id") if isinstance(msg, dict) else getattr(msg, "id", None)
    if isinstance(mid, str) and mid:
        return mid
    tc_id = msg.get("tool_call_id") if isinstance(msg, dict) else getattr(msg, "tool_call_id", None)
    txt = _extract_message_text(msg)
    digest = hashlib.sha256(f"{idx}:{tc_id}:{txt}".encode("utf-8", "ignore")).hexdigest()[:16]
    return f"hist-{idx}-{digest}"


def _derive_session_id(history: Sequence[Any], explicit_session_id: Optional[str]) -> str:
    if explicit_session_id:
        return _safe_label(explicit_session_id, limit=96)
    if history:
        first = history[0]
        fid = first.get("id") if isinstance(first, dict) else getattr(first, "id", None)
        if isinstance(fid, str) and fid:
            return _safe_label(f"inspect-{fid}", limit=96)
        seed = f"{_msg_role(first)}:{_extract_message_text(first)[:512]}"
        digest = hashlib.sha256(seed.encode("utf-8", "ignore")).hexdigest()[:16]
        return f"inspect-{digest}"
    return "inspect-default-sample"


def _consequence_for_call(name: str, args: Any) -> Tuple[str, float, int]:
    low = (name or "").lower()
    if any(h in low for h in ("delete", "remove", "drop", "wipe", "destroy", "truncate")):
        return "destructive", 0.0, 0
    if any(h in low for h in ("transfer", "pay", "wire", "payout", "withdraw", "purchase")):
        amt = 0.0
        if isinstance(args, dict):
            for k in ("amount", "value", "total"):
                try:
                    amt = max(amt, float(args[k]))
                except (KeyError, TypeError, ValueError):
                    pass
        return "spend", amt, 0
    try:
        raw_bytes = len(json.dumps(args, default=str).encode("utf-8"))
    except Exception:
        raw_bytes = 0
    if _looks_external(args, name) or any(
        h in low for h in ("http", "post", "fetch", "request", "webhook", "url", "send", "email", "slack", "upload")
    ):
        return "egress", 0.0, min(raw_bytes, _MAX_OBSERVED_TOOL_BYTES)
    return "action", 0.0, 0


@dataclass
class _SessionState:
    policy: ModelProxyPolicy
    seen_tool_msg_ids: set


class AdomInspectEngine:
    """Stateful deterministic evaluator backing `adom_approver` across multi-turn Inspect samples."""

    def __init__(
        self,
        *,
        mode: str = "enforce",  # "enforce" | "control_prefilter" | "observe"
        allowed_tools: Iterable[str] = (),
        approved_outbound: Iterable[str] = (),
        approved_payees: Iterable[str] = (),
        allowed_delete_paths: Iterable[str] = (),
        taint_values: Iterable[str] = (),
        strict_deny_unknown: bool = True,
        deny_sensitive_egress: bool = False,
        terminate_on_breaker: bool = True,
        max_actions: int = 200,
        max_destructive: int = 3,
        max_spend: float = 0.0,
        max_failures: int = 5,
        window_seconds: float = 60.0,
        session_id: Optional[str] = None,
        audit_log_path: Optional[Path] = None,
        audit_key: Optional[bytes] = None,
    ):
        if mode not in ("enforce", "control_prefilter", "observe"):
            raise ValueError(f"unsupported mode {mode!r}; expected enforce, control_prefilter, or observe")
        self.mode = mode
        self.allowed_tools = tuple(allowed_tools)
        self.approved_outbound = tuple(approved_outbound)
        self.approved_payees = tuple(approved_payees)
        self.allowed_delete_paths = tuple(allowed_delete_paths)
        self.taint_values = tuple(taint_values)
        self.strict_deny_unknown = strict_deny_unknown
        self.deny_sensitive_egress = deny_sensitive_egress
        self.terminate_on_breaker = terminate_on_breaker
        self.explicit_session_id = session_id

        self.blast = BlastRadiusController(
            default_budget=Budget(
                max_actions=max_actions,
                max_destructive=max_destructive,
                max_spend=max_spend,
                max_failures=max_failures,
                window_seconds=window_seconds,
            ),
            strict_unknown_agents=False,
        )
        self.audit_log: Optional[ChainLog] = (
            ChainLog(audit_log_path, key=audit_key) if audit_log_path is not None else None
        )
        self._sessions: "collections.OrderedDict[str, _SessionState]" = collections.OrderedDict()
        self._lock = threading.RLock()

    def _get_session(self, sid: str) -> _SessionState:
        with self._lock:
            st = self._sessions.get(sid)
            if st is not None:
                self._sessions.move_to_end(sid)
                return st
            pol = ModelProxyPolicy(
                taint_values=list(self.taint_values),
                approved_outbound=list(self.approved_outbound),
                approved_payees=list(self.approved_payees),
                allowed_delete_paths=list(self.allowed_delete_paths),
                allowed_tools=self.allowed_tools,
                strict_deny_unknown=self.strict_deny_unknown,
                deny_sensitive_egress=self.deny_sensitive_egress,
                track_session=True,
                block_mode=True,
            ).seal()
            st = _SessionState(policy=pol, seen_tool_msg_ids=set())
            self._sessions[sid] = st
            while len(self._sessions) > _MAX_SESSIONS:
                self._sessions.popitem(last=False)
            return st

    def _ingest_history(self, st: _SessionState, history: Sequence[Any]) -> int:
        learned = 0
        for idx, msg in enumerate(history or ()):
            if _msg_role(msg) != "tool":
                continue
            mid = _msg_id_or_digest(msg, idx)
            if mid in st.seen_tool_msg_ids:
                continue
            st.seen_tool_msg_ids.add(mid)
            txt = _extract_message_text(msg)
            if not txt:
                continue
            fn_name = msg.get("function") if isinstance(msg, dict) else getattr(msg, "function", None)
            label = f"inspect_tool:{_safe_label(str(fn_name or 'tool'))}"
            st.policy.note_read(txt, path=label, untrusted=True)
            learned += 1
        return learned

    def decide_call(
        self,
        message: str,
        call: Any,
        view: Any = None,
        history: Sequence[Any] = (),
    ) -> Any:
        t0 = time.perf_counter()
        sid = _derive_session_id(history, self.explicit_session_id)
        try:
            st = self._get_session(sid)
            with self._lock:
                learned = self._ingest_history(st, history)

                if isinstance(call, dict):
                    fn_name = call.get("function")
                    raw_args = call.get("arguments", {})
                    parse_error = call.get("parse_error")
                    call_id = str(call.get("id") or "")
                else:
                    fn_name = getattr(call, "function", None)
                    raw_args = getattr(call, "arguments", {})
                    parse_error = getattr(call, "parse_error", None)
                    call_id = str(getattr(call, "id", "") or "")

                if parse_error:
                    self.blast.record_failure(sid)
                    return self._finish(
                        t0=t0,
                        sid=sid,
                        call_id=call_id,
                        tool=str(fn_name or "<malformed>"),
                        blocked=True,
                        breaker_tripped=(self.blast.state_of(sid) == "open"),
                        reason=f"ToolCall parse_error fail-closed: {_safe_label(str(parse_error))}",
                        signals=["inspect:parse_error:fail_closed"],
                        learned=learned,
                    )

                if not isinstance(fn_name, str) or not fn_name.strip():
                    self.blast.record_failure(sid)
                    return self._finish(
                        t0=t0,
                        sid=sid,
                        call_id=call_id,
                        tool="<empty>",
                        blocked=True,
                        breaker_tripped=(self.blast.state_of(sid) == "open"),
                        reason="Missing or non-string ToolCall.function",
                        signals=["inspect:missing_function:fail_closed"],
                        learned=learned,
                    )

                kind, amt, nbytes = _consequence_for_call(fn_name, raw_args)
                bv = self.blast.check(sid, kind=kind, amount=amt, nbytes=nbytes)
                if not bv.allowed:
                    return self._finish(
                        t0=t0,
                        sid=sid,
                        call_id=call_id,
                        tool=fn_name,
                        blocked=True,
                        breaker_tripped=True,
                        reason=bv.reason,
                        signals=list(bv.signals) + ["inspect:blast_radius_blocked"],
                        learned=learned,
                    )

                _frozen, v = screen_action(st.policy, fn_name, raw_args if raw_args is not None else {})
                sigs = list(bv.signals) + list(v.signals)

                arg_strings: List[str] = []
                _collect_strings(_frozen if _frozen is not None else raw_args, arg_strings)
                cred_hit: Optional[str] = None
                for val in arg_strings:
                    cred_hit = tiers.credential_label(val) or tiers.credential_dir_label(val)
                    if cred_hit:
                        break
                    fn_norm = val.strip().replace("\\", "/")
                    if tiers._DOTENV_RX.search(fn_norm) and not tiers._DOTENV_SAFE_RX.search(fn_norm):
                        cred_hit = "dotenv_secret_file"
                        break
                if cred_hit:
                    self.blast.record_failure(sid)
                    tripped = self.blast.state_of(sid) == "open"
                    return self._finish(
                        t0=t0,
                        sid=sid,
                        call_id=call_id,
                        tool=fn_name,
                        blocked=True,
                        breaker_tripped=tripped,
                        reason=f"ADOM blocked credential store access ({cred_hit})",
                        signals=sigs + [f"tier:credential_path:{cred_hit}"],
                        learned=learned,
                    )

                if v.action == "block":
                    self.blast.record_failure(sid)
                    tripped = self.blast.state_of(sid) == "open"
                    return self._finish(
                        t0=t0,
                        sid=sid,
                        call_id=call_id,
                        tool=fn_name,
                        blocked=True,
                        breaker_tripped=tripped,
                        reason=v.reason or f"ADOM denied tool '{_safe_label(fn_name)}'",
                        signals=sigs,
                        learned=learned,
                    )

                self.blast.record_success(sid)
                return self._finish(
                    t0=t0,
                    sid=sid,
                    call_id=call_id,
                    tool=fn_name,
                    blocked=False,
                    breaker_tripped=False,
                    reason="ADOM deterministic checks passed",
                    signals=sigs,
                    learned=learned,
                )
        except Exception as exc:
            self.blast.record_failure(sid)
            return self._finish(
                t0=t0,
                sid=sid,
                call_id="",
                tool="<error>",
                blocked=True,
                breaker_tripped=(self.blast.state_of(sid) == "open"),
                reason=f"ADOM approver internal error fail-closed: {type(exc).__name__}",
                signals=["inspect:internal_error:fail_closed"],
                learned=0,
            )

    def _finish(
        self,
        *,
        t0: float,
        sid: str,
        call_id: str,
        tool: str,
        blocked: bool,
        breaker_tripped: bool,
        reason: str,
        signals: List[str],
        learned: int,
    ) -> Any:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if self.mode == "observe":
            decision = "approve"
        elif blocked:
            decision = "terminate" if (breaker_tripped and self.terminate_on_breaker) else "reject"
        elif self.mode == "control_prefilter":
            decision = "escalate"
        else:
            decision = "approve"

        seq = 0
        digest = ""
        if self.audit_log is not None:
            rec = {
                "ts": round(time.time(), 6),
                "component": "inspect_approver",
                "mode": self.mode,
                "session_id": sid,
                "call_id": call_id,
                "tool": _safe_label(tool),
                "would_block": blocked,
                "decision": decision,
                "reason": reason,
                "signals": signals,
                "history_tool_messages_ingested": learned,
                "latency_ms": round(elapsed_ms, 4),
            }
            digest = self.audit_log.append(rec)
            seq = rec.get("seq", 0)

        explanation = (
            f"ADOM [{self.mode}] {decision}: {reason}"
            if blocked or self.mode != "enforce"
            else "ADOM approved tool call"
        )
        meta: Dict[str, Any] = {
            "adom_mode": self.mode,
            "adom_session_id": sid,
            "adom_would_block": blocked,
            "adom_breaker_tripped": breaker_tripped,
            "adom_signals": signals,
            "adom_history_ingested": learned,
            "adom_latency_ms": round(elapsed_ms, 4),
        }
        if digest:
            meta["adom_audit_seq"] = seq
            meta["adom_audit_hash"] = digest
        return _make_approval(decision=decision, explanation=explanation, metadata=meta)


def create_adom_approver(
    mode: str = "enforce",
    allowed_tools: Sequence[str] = (),
    approved_outbound: Sequence[str] = (),
    approved_payees: Sequence[str] = (),
    allowed_delete_paths: Sequence[str] = (),
    taint_values: Sequence[str] = (),
    strict_deny_unknown: bool = True,
    deny_sensitive_egress: bool = False,
    terminate_on_breaker: bool = True,
    max_actions: int = 200,
    max_destructive: int = 3,
    max_spend: float = 0.0,
    max_failures: int = 5,
    window_seconds: float = 60.0,
    session_id: Optional[str] = None,
    audit_log_path: Optional[str] = None,
    audit_key_file: Optional[str] = None,
) -> Callable[..., Any]:
    """Build an async `inspect_ai`-compatible `Approver` callable backed by `AdomInspectEngine`."""
    log_path = Path(audit_log_path).expanduser() if audit_log_path else None
    key_bytes = load_key(Path(audit_key_file).expanduser()) if audit_key_file else None
    engine = AdomInspectEngine(
        mode=mode,
        allowed_tools=allowed_tools,
        approved_outbound=approved_outbound,
        approved_payees=approved_payees,
        allowed_delete_paths=allowed_delete_paths,
        taint_values=taint_values,
        strict_deny_unknown=strict_deny_unknown,
        deny_sensitive_egress=deny_sensitive_egress,
        terminate_on_breaker=terminate_on_breaker,
        max_actions=max_actions,
        max_destructive=max_destructive,
        max_spend=max_spend,
        max_failures=max_failures,
        window_seconds=window_seconds,
        session_id=session_id,
        audit_log_path=log_path,
        audit_key=key_bytes,
    )

    async def approve(
        message: str,
        call: Any,
        view: Any,
        history: List[Any],
    ) -> Any:
        return engine.decide_call(message=message, call=call, view=view, history=history)

    approve.engine = engine  # type: ignore[attr-defined]
    return approve


if _inspect_approver_decorator is not None:
    adom_approver = _inspect_approver_decorator(name="adom_approver")(create_adom_approver)
else:
    adom_approver = create_adom_approver


def generate_inspect_policy_yaml(
    *,
    mode: str = "enforce",
    allowed_tools: Sequence[str] = ("read_file", "search_docs", "http_post"),
    approved_outbound: Sequence[str] = ("api.internal.example",),
    downstream_approver: str = "human",
    audit_log_path: str = "~/.adom/inspect/decisions.jsonl",
) -> str:
    """Emit an `inspect eval --approval <file.yaml>` policy configuration."""
    tools_yaml = "[" + ", ".join(f'"{t}"' for t in allowed_tools) + "]"
    hosts_yaml = "[" + ", ".join(f'"{h}"' for h in approved_outbound) + "]"
    strict_val = "true" if allowed_tools else "false"
    base = f'''# UK AISI Inspect (`inspect_ai`) approval policy backed by ADOM
# Run with:
#   inspect eval inspect_evals/b3 --approval adom-approval.yaml
#   inspect eval inspect_evals/mcptox --approval adom-approval.yaml
approvers:
  - name: adom_agent_security/adom_approver
    tools: "*"
    mode: "{mode}"
    allowed_tools: {tools_yaml}
    approved_outbound: {hosts_yaml}
    strict_deny_unknown: {strict_val}
    terminate_on_breaker: true
    max_failures: 5
    audit_log_path: "{audit_log_path}"
'''
    if mode == "control_prefilter":
        base += f'''
  # Stage 2 only runs when ADOM returns decision="escalate" (schema + taint + SSRF clean),
  # shielding `suspend_limits()` LLM/human monitors from deterministic attacks & retry loops.
  - name: {downstream_approver}
    tools: "*"
'''
    return base
