"""ADOM HTTP Guardrail Service & Reference Architecture for Kong AI Gateway (3.14+).

Integrates ADOM's deterministic, zero-LLM enforcement core with Kong AI Gateway across
both LLM and MCP traffic planes:

1. **LLM Plane (`ai-custom-guardrail`, `guarding_mode: BOTH`)** — `POST /v1/kong/guardrail`
   - Safely parses multi-turn agent histories across OpenAI Chat (`/v1/chat/completions`),
     OpenAI Responses (`/v1/responses`), Anthropic Messages (`/v1/messages`), Gemini
     (`generateContent`), and flat `$(content)` text payloads—including `assistant`
     messages with `content: null` + `tool_calls` and multimodal content arrays that
     cause `ai-prompt-guard` (`guard-prompt.lua`) to reject valid tool-calling turns
     when `match_all_roles=true`.
   - Learns untrusted/sensitive tool outputs (`role="tool"`, `function_call_output`,
     `tool_result`, `functionResponse`) into bounded per-session taint memory on `INPUT`.
   - Screens `OUTPUT` tool calls (`tool_calls`, `function_call`, `tool_use`,
     `functionCall`) and assistant text for raw/encoded secret exfiltration (`base64`,
     `hex`, URL-encoded, reversed, chunked), SSRF destinations, ungranted tools
     (`strict_deny_unknown=True`), and sliding-window consequence/retry budgets
     (`BlastRadiusController`).

2. **MCP Plane (`ai-mcp-proxy` `passthrough-listener` -> `adom mcp-http`)**
   - Kong's `ai-mcp-proxy` enforces Consumer/Group ACLs on tool names but explicitly
     documents `AI Guardrails: supported: false` on MCP routes. Placing `McpHttpProxyServer`
     (`adom mcp-http`) as the upstream service behind Kong's `passthrough-listener` adds
     argument-level policy screening, cross-tool taint tracking, strict SSRF IP-pinning,
     and tamper-evident SHA-256 `ChainLog` audit receipts.

Pure Python 3.10+ standard library; zero external runtime dependencies.
"""
from __future__ import annotations

import collections
import http.server
import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from adom.api.model_proxy import (
    ModelProxyPolicy,
    _SECRET_RX,
    _collect_strings,
    _encoded_secret_hit,
    _looks_external,
    _pii_hit,
    _safe_label,
    _scan_windows,
)
from adom.enforcement.action_kernel import screen_action
from adom.enforcement.audit_chain import ChainLog
from adom.enforcement.blast_radius import BlastRadiusController, Budget

_MAX_HTTP_BODY = 4 * 1024 * 1024  # 4 MiB hard cap on guardrail HTTP payloads (DoS bound)
_MAX_SESSIONS = 1024              # bounded LRU of active agent sessions
_MAX_REGEX_TEXT = 65536           # bounded prompt text evaluated against optional regex rules


def _extract_content_text(content: Any) -> str:
    """Safely extract text from string, null, or multimodal/structured block arrays."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for item in content[:256]:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                btype = item.get("type")
                if btype in ("text", "input_text", "output_text") and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item.get("content"), str):
                    parts.append(item["content"])
                elif isinstance(item.get("content"), list):
                    nested = _extract_content_text(item["content"])
                    if nested:
                        parts.append(nested)
        return "\n".join(p for p in parts if p)
    if isinstance(content, dict):
        if isinstance(content.get("text"), str):
            return content["text"]
        vals: List[str] = []
        _collect_strings(content, vals)
        return "\n".join(vals)
    return ""


def _parse_json_maybe(value: Any) -> Any:
    if isinstance(value, str):
        s = value.strip()
        if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
            try:
                return json.loads(s)
            except ValueError:
                return value
    return value


def _extract_input_artifacts(payload: Any) -> Tuple[List[str], List[Tuple[str, str]], List[Tuple[str, Any]]]:
    """Extract (prompt_texts, tool_observations[(label, text)], embedded_tool_calls[(name, args)])
    from any supported LLM request shape without rejecting null/array assistant content."""
    prompts: List[str] = []
    observations: List[Tuple[str, str]] = []
    tool_calls: List[Tuple[str, Any]] = []

    if isinstance(payload, str):
        prompts.append(payload)
        return prompts, observations, tool_calls
    if not isinstance(payload, dict):
        return prompts, observations, tool_calls

    if isinstance(payload.get("text"), str):
        prompts.append(payload["text"])
    if isinstance(payload.get("prompt"), str):
        prompts.append(payload["prompt"])

    # 1. OpenAI / Anthropic `messages[]`
    messages = payload.get("messages")
    if isinstance(messages, list):
        for msg in messages[:512]:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role") or "")
            content = msg.get("content")
            if role == "tool":
                label = str(msg.get("name") or msg.get("tool_call_id") or "tool_output")
                obs_text = _extract_content_text(content)
                if obs_text:
                    observations.append((f"tool:{_safe_label(label)}", obs_text))
                continue

            # Anthropic `user` messages frequently carry `tool_result` blocks
            if isinstance(content, list):
                for block in content[:256]:
                    if not isinstance(block, dict):
                        continue
                    btype = block.get("type")
                    if btype == "tool_result":
                        tid = str(block.get("tool_use_id") or "tool_result")
                        obs_text = _extract_content_text(block.get("content"))
                        if obs_text:
                            observations.append((f"tool_result:{_safe_label(tid)}", obs_text))
                    elif btype == "tool_use":
                        tname = str(block.get("name") or "")
                        if tname:
                            tool_calls.append((tname, block.get("input", {})))

            txt = _extract_content_text(content)
            if txt and role in ("user", "system", "developer", "assistant"):
                prompts.append(txt)

            # Historical assistant `tool_calls` (OpenAI format)
            if role == "assistant" and isinstance(msg.get("tool_calls"), list):
                for tc in msg["tool_calls"][:64]:
                    if isinstance(tc, dict) and isinstance(tc.get("function"), dict):
                        fn = tc["function"]
                        tname = str(fn.get("name") or "")
                        if tname:
                            tool_calls.append((tname, _parse_json_maybe(fn.get("arguments", {}))))

    # 2. OpenAI Responses API `input[]`
    resp_input = payload.get("input")
    if isinstance(resp_input, str):
        prompts.append(resp_input)
    elif isinstance(resp_input, list):
        for item in resp_input[:512]:
            if not isinstance(item, dict):
                continue
            itype = item.get("type")
            if itype == "function_call_output":
                cid = str(item.get("call_id") or "function_call_output")
                out_txt = _extract_content_text(item.get("output"))
                if out_txt:
                    observations.append((f"responses_tool:{_safe_label(cid)}", out_txt))
            else:
                txt = _extract_content_text(item.get("content"))
                if txt:
                    prompts.append(txt)

    # 3. Gemini `contents[]`
    gem_contents = payload.get("contents")
    if isinstance(gem_contents, list):
        for item in gem_contents[:512]:
            if not isinstance(item, dict):
                continue
            for part in (item.get("parts") or [])[:128]:
                if not isinstance(part, dict):
                    continue
                if isinstance(part.get("text"), str):
                    prompts.append(part["text"])
                if isinstance(part.get("functionResponse"), dict):
                    fr = part["functionResponse"]
                    fname = str(fr.get("name") or "gemini_tool")
                    obs_text = json.dumps(fr.get("response", {}), default=str)
                    observations.append((f"gemini:{_safe_label(fname)}", obs_text))

    return prompts, observations, tool_calls


def _extract_output_artifacts(payload: Any) -> Tuple[List[Tuple[str, Any]], List[str]]:
    """Extract (proposed_tool_calls[(name, args)], assistant_texts) from an LLM response."""
    calls: List[Tuple[str, Any]] = []
    texts: List[str] = []

    if isinstance(payload, str):
        texts.append(payload)
        return calls, texts
    if not isinstance(payload, dict):
        return calls, texts

    if isinstance(payload.get("text"), str):
        texts.append(payload["text"])

    # 1. OpenAI Chat Completions: `choices[].message`
    for choice in (payload.get("choices") or [])[:32]:
        if not isinstance(choice, dict):
            continue
        msg = choice.get("message")
        if isinstance(msg, dict):
            txt = _extract_content_text(msg.get("content"))
            if txt:
                texts.append(txt)
            for tc in (msg.get("tool_calls") or [])[:64]:
                if isinstance(tc, dict) and isinstance(tc.get("function"), dict):
                    fn = tc["function"]
                    calls.append((str(fn.get("name") or ""), _parse_json_maybe(fn.get("arguments", {}))))

    # 2. OpenAI Responses API: `output[]`
    for item in (payload.get("output") or [])[:128]:
        if not isinstance(item, dict):
            continue
        itype = item.get("type")
        if itype in ("function_call", "custom_tool_call", "tool_call"):
            raw_args = item.get("arguments", item.get("input", {}))
            calls.append((str(item.get("name") or ""), _parse_json_maybe(raw_args)))
        elif itype == "message":
            txt = _extract_content_text(item.get("content"))
            if txt:
                texts.append(txt)

    # 3. Anthropic Messages API: `content[]`
    if isinstance(payload.get("content"), list):
        for block in payload["content"][:128]:
            if not isinstance(block, dict):
                continue
            btype = block.get("type")
            if btype == "tool_use":
                calls.append((str(block.get("name") or ""), block.get("input", {})))
            elif btype == "text" and isinstance(block.get("text"), str):
                texts.append(block["text"])

    # 4. Gemini API: `candidates[].content.parts[]`
    for cand in (payload.get("candidates") or [])[:16]:
        if not isinstance(cand, dict):
            continue
        cobj = cand.get("content")
        if not isinstance(cobj, dict):
            continue
        for part in (cobj.get("parts") or [])[:64]:
            if not isinstance(part, dict):
                continue
            if isinstance(part.get("functionCall"), dict):
                fc = part["functionCall"]
                calls.append((str(fc.get("name") or ""), fc.get("args", {})))
            elif isinstance(part.get("text"), str):
                texts.append(part["text"])

    # 5. Direct single tool-call envelope `{"tool_name": ..., "arguments": ...}`
    if "tool_name" in payload and isinstance(payload.get("tool_name"), str):
        calls.append((payload["tool_name"], _parse_json_maybe(payload.get("arguments", {}))))

    return calls, texts


def _consequence_for_call(name: str, args: Any) -> Tuple[str, float, int]:
    """Classify (kind, spend_amount, egress_bytes) for BlastRadiusController accounting."""
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
        return "egress", 0.0, min(raw_bytes, 262144)
    return "action", 0.0, 0


@dataclass
class GuardrailVerdict:
    block: bool
    phase: str
    session_id: str
    block_reason: str = ""
    block_message: str = ""
    signals: List[str] = field(default_factory=list)
    blocked_tools: List[str] = field(default_factory=list)
    audit_seq: int = 0
    audit_hash: str = ""
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "block": self.block,
            "action": "block" if self.block else "allow",
            "phase": self.phase,
            "session_id": self.session_id,
            "block_reason": self.block_reason,
            "block_message": self.block_message or ("blocked by ADOM guardrail" if self.block else "allowed"),
            "signals": list(self.signals),
            "blocked_tools": list(self.blocked_tools),
            "audit_seq": self.audit_seq,
            "audit_hash": self.audit_hash,
            "latency_ms": round(self.latency_ms, 4),
        }


class KongGuardrailEngine:
    """Stateful, fail-closed ADOM decision engine for Kong `ai-custom-guardrail`."""

    def __init__(
        self,
        *,
        allowed_tools: Iterable[str] = (),
        approved_outbound: Iterable[str] = (),
        approved_payees: Iterable[str] = (),
        allowed_delete_paths: Iterable[str] = (),
        taint_values: Iterable[str] = (),
        strict_deny_unknown: bool = True,
        deny_sensitive_egress: bool = False,
        deny_patterns: Iterable[str] = (),
        budget: Optional[Budget] = None,
        audit_log_path: Optional[Path] = None,
        audit_key: Optional[bytes] = None,
        max_sessions: int = _MAX_SESSIONS,
    ):
        self.allowed_tools = tuple(allowed_tools)
        self.approved_outbound = tuple(approved_outbound)
        self.approved_payees = tuple(approved_payees)
        self.allowed_delete_paths = tuple(allowed_delete_paths)
        self.taint_values = tuple(taint_values)
        self.strict_deny_unknown = strict_deny_unknown
        self.deny_sensitive_egress = deny_sensitive_egress
        self.deny_regexes = tuple(re.compile(p, re.I) for p in deny_patterns)
        self.max_sessions = max(16, int(max_sessions))

        self.blast = BlastRadiusController(
            default_budget=budget or Budget(max_actions=200, max_destructive=3, max_spend=0.0, max_failures=5),
            strict_unknown_agents=False,
        )
        self.audit_log: Optional[ChainLog] = (
            ChainLog(audit_log_path, key=audit_key) if audit_log_path is not None else None
        )
        self._sessions: "collections.OrderedDict[str, ModelProxyPolicy]" = collections.OrderedDict()
        self._lock = threading.RLock()

    def _get_session_policy(self, session_id: str) -> ModelProxyPolicy:
        with self._lock:
            pol = self._sessions.get(session_id)
            if pol is not None:
                self._sessions.move_to_end(session_id)
                return pol
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
            self._sessions[session_id] = pol
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
            return pol

    def _scan_text_for_taints(self, policy: ModelProxyPolicy, text: str) -> Optional[str]:
        if not text:
            return None
        taints = policy.all_taints()
        windows = _scan_windows(text[:262144])
        for idx, win in enumerate(windows):
            hit = _encoded_secret_hit(win, taints, deep=(idx == 0))
            if hit:
                return f"output_text:exfil:{hit}"
        for rx, label in _SECRET_RX:
            if any(rx.search(win) for win in windows):
                return f"output_text:secret_pattern:{label}"
        if policy._sensitive_read:
            pii = _pii_hit(text)
            if pii:
                return f"output_text:pii_exfil:{pii}:critical"
        return None

    def evaluate(
        self,
        envelope: Any,
        *,
        headers: Optional[Dict[str, str]] = None,
    ) -> GuardrailVerdict:
        t0 = time.perf_counter()
        hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        session_id = "default-kong-session"
        phase = "INPUT"

        try:
            if not isinstance(envelope, dict):
                raise ValueError("guardrail request body must be a JSON object")

            for hk in ("x-kong-session-id", "x-session-id", "x-consumer-custom-id", "x-consumer-id", "x-consumer-username"):
                if hdrs.get(hk, "").strip():
                    session_id = _safe_label(hdrs[hk].strip(), limit=96)
                    break
            for bk in ("session_id", "conversation_id"):
                if isinstance(envelope.get(bk), str) and envelope[bk].strip():
                    session_id = _safe_label(envelope[bk].strip(), limit=96)
                    break

            raw_source = str(envelope.get("source") or envelope.get("phase") or hdrs.get("x-kong-guard-phase") or "").upper()
            if raw_source in ("INPUT", "OUTPUT"):
                phase = raw_source
            elif any(k in envelope for k in ("choices", "candidates", "output")) or (
                isinstance(envelope.get("content"), list)
                and any(isinstance(b, dict) and b.get("type") == "tool_use" for b in envelope["content"])
            ):
                phase = "OUTPUT"

            # Unwrap nested `payload` / `body` / `request` / `response` if wrapped by Kong `config.request.body`
            inner: Any = envelope
            for key in ("payload", "body", "request", "response"):
                if key in envelope and envelope[key] is not None:
                    inner = _parse_json_maybe(envelope[key])
                    break
            if inner is envelope and "text" in envelope and len(envelope) <= 4 and isinstance(envelope.get("text"), str):
                parsed_text = _parse_json_maybe(envelope["text"])
                inner = parsed_text

            policy = self._get_session_policy(session_id)

            if phase == "INPUT":
                bv = self.blast.check(session_id, kind="action")
                if not bv.allowed:
                    return self._finalize(
                        t0=t0,
                        block=True,
                        phase=phase,
                        session_id=session_id,
                        block_reason="blast_radius_exceeded",
                        block_message=f"ADOM blocked request: {bv.reason}",
                        signals=list(bv.signals),
                    )

                prompts, observations, _hist_calls = _extract_input_artifacts(inner)
                for label, obs_text in observations:
                    policy.note_read(obs_text, path=label, untrusted=True)

                if self.deny_regexes:
                    joined = "\n".join(prompts)[:_MAX_REGEX_TEXT]
                    all_obs = "\n".join(t for _, t in observations)[:_MAX_REGEX_TEXT]
                    scan_target = f"{joined}\n{all_obs}"
                    for rx in self.deny_regexes:
                        if rx.search(scan_target):
                            self.blast.record_failure(session_id)
                            return self._finalize(
                                t0=t0,
                                block=True,
                                phase=phase,
                                session_id=session_id,
                                block_reason="prompt_deny_pattern",
                                block_message="ADOM blocked request matching configured deny pattern",
                                signals=["input:deny_pattern:high"],
                            )

                self.blast.record_success(session_id)
                return self._finalize(
                    t0=t0,
                    block=False,
                    phase=phase,
                    session_id=session_id,
                    signals=["adom:input:ok"] + (["adom:taint_observed"] if observations else []),
                )

            # OUTPUT phase: inspect tool calls + assistant text
            calls, texts = _extract_output_artifacts(inner)
            signals: List[str] = []
            blocked_tools: List[str] = []
            reasons: List[str] = []

            if not calls:
                bv = self.blast.check(session_id, kind="action")
                if not bv.allowed:
                    return self._finalize(
                        t0=t0,
                        block=True,
                        phase=phase,
                        session_id=session_id,
                        block_reason="blast_radius_exceeded",
                        block_message=f"ADOM blocked response: {bv.reason}",
                        signals=list(bv.signals),
                    )

            for tname, targs in calls:
                kind, amt, nbytes = _consequence_for_call(tname, targs)
                bv = self.blast.check(session_id, kind=kind, amount=amt, nbytes=nbytes)
                if not bv.allowed:
                    signals.extend(bv.signals)
                    blocked_tools.append(_safe_label(tname or "<empty>"))
                    reasons.append(bv.reason)
                    continue

                _frozen, v = screen_action(policy, tname, targs)
                signals.extend(v.signals)
                if v.action == "block":
                    self.blast.record_failure(session_id)
                    blocked_tools.append(_safe_label(tname or "<empty>"))
                    reasons.append(v.reason or f"tool '{_safe_label(tname)}' denied by ADOM")

            for txt in texts:
                text_hit = self._scan_text_for_taints(policy, txt)
                if text_hit:
                    self.blast.record_failure(session_id)
                    signals.append(text_hit)
                    reasons.append("assistant response leaks tainted secret or sensitive PII")
                    break

            if reasons:
                primary = signals[0] if signals else "output_policy_violation"
                return self._finalize(
                    t0=t0,
                    block=True,
                    phase=phase,
                    session_id=session_id,
                    block_reason=primary,
                    block_message="ADOM blocked response: " + "; ".join(reasons),
                    signals=signals,
                    blocked_tools=blocked_tools,
                )

            self.blast.record_success(session_id)
            return self._finalize(
                t0=t0,
                block=False,
                phase=phase,
                session_id=session_id,
                signals=signals or ["adom:output:ok"],
            )
        except Exception as exc:
            self.blast.record_failure(session_id)
            return self._finalize(
                t0=t0,
                block=True,
                phase=phase,
                session_id=session_id,
                block_reason="guardrail_fail_closed",
                block_message=f"ADOM guardrail fail-closed: {type(exc).__name__}",
                signals=["kong_guardrail:fail_closed"],
            )

    def _finalize(
        self,
        *,
        t0: float,
        block: bool,
        phase: str,
        session_id: str,
        block_reason: str = "",
        block_message: str = "",
        signals: Optional[List[str]] = None,
        blocked_tools: Optional[List[str]] = None,
    ) -> GuardrailVerdict:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        sigs = list(signals or [])
        btools = list(blocked_tools or [])
        seq = 0
        digest = ""
        if self.audit_log is not None:
            record = {
                "ts": round(time.time(), 6),
                "component": "kong_guardrail",
                "session_id": session_id,
                "phase": phase,
                "verdict": "block" if block else "allow",
                "block_reason": block_reason,
                "signals": sigs,
                "blocked_tools": btools,
                "latency_ms": round(elapsed_ms, 4),
            }
            digest = self.audit_log.append(record)
            seq = record.get("seq", 0)
        return GuardrailVerdict(
            block=block,
            phase=phase,
            session_id=session_id,
            block_reason=block_reason,
            block_message=block_message,
            signals=sigs,
            blocked_tools=btools,
            audit_seq=seq,
            audit_hash=digest,
            latency_ms=elapsed_ms,
        )


class KongGuardrailServer:
    """Threaded HTTP server exposing `/v1/kong/guardrail` and `/healthz` for Kong 3.14+."""

    def __init__(
        self,
        engine: KongGuardrailEngine,
        *,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
    ):
        self.engine = engine
        srv_ref = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _write_json(self, status: int, body_obj: Dict[str, Any]) -> None:
                encoded = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def do_GET(self) -> None:  # noqa: N802
                if self.path.split("?", 1)[0] in ("/healthz", "/health"):
                    self._write_json(200, {"ok": True, "service": "adom-kong-guardrail"})
                    return
                self._write_json(404, {"block": True, "block_message": "unknown endpoint"})

            def do_POST(self) -> None:  # noqa: N802
                route = self.path.split("?", 1)[0]
                if route != "/v1/kong/guardrail":
                    self._write_json(404, {"block": True, "block_message": "unknown endpoint"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    verdict = srv_ref.engine.evaluate(None, headers=dict(self.headers.items()))
                    self._write_json(200, verdict.to_dict())
                    return
                if length < 0 or length > _MAX_HTTP_BODY:
                    self._write_json(
                        200,
                        {
                            "block": True,
                            "action": "block",
                            "block_reason": "body_too_large_fail_closed",
                            "block_message": "ADOM blocked payload exceeding max guardrail body size",
                            "signals": ["kong_guardrail:body_too_large:fail_closed"],
                        },
                    )
                    return
                raw = self.rfile.read(length) if length > 0 else b""
                try:
                    parsed = json.loads(raw.decode("utf-8"))
                except Exception:
                    parsed = None
                verdict = srv_ref.engine.evaluate(parsed, headers=dict(self.headers.items()))
                # Kong `ai-custom-guardrail` expects HTTP 200 JSON from the guardrail service
                # and reads `resp.block` + `resp.block_message` to reject (HTTP 400/403) or allow.
                self._write_json(200, verdict.to_dict())

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

        self._httpd = http.server.ThreadingHTTPServer((bind_host, bind_port), _Handler)
        self.port = self._httpd.server_address[1]
        self._thread: Optional[threading.Thread] = None

    @property
    def guardrail_url(self) -> str:
        host = self._httpd.server_address[0]
        return f"http://{host}:{self.port}/v1/kong/guardrail"

    def start(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)


def generate_deck_config(
    *,
    guardrail_url: str = "http://adom-guardrail:8780/v1/kong/guardrail",
    adom_mcp_upstream_url: str = "http://adom-mcp-proxy:8765/mcp",
    llm_model: str = "gpt-4o",
) -> str:
    """Emit a declarative Kong `decK` (`_format_version: "3.0"`) configuration pairing
    Kong AI Gateway 3.14+ (`ai-proxy-advanced`, `ai-custom-guardrail`, `ai-mcp-proxy`)
    with ADOM across both LLM and MCP routes."""
    return f'''_format_version: "3.0"

services:
  - name: enterprise-llm-service
    url: https://api.openai.com/v1/chat/completions
    routes:
      - name: llm-chat-route
        paths:
          - /llm/v1/chat
        plugins:
          - name: ai-proxy-advanced
            config:
              targets:
                - route_type: llm/v1/chat
                  auth:
                    header_name: Authorization
                    header_value: Bearer ${{{{ env "DECK_OPENAI_API_KEY" }}}}
                  model:
                    provider: openai
                    name: {llm_model}
          - name: ai-custom-guardrail
            config:
              guarding_mode: BOTH
              text_source: concatenate_all_content
              params:
                adom_url: "{guardrail_url}"
              request:
                url: "$(conf.params.adom_url)"
                headers:
                  Content-Type: application/json
                body:
                  source: "$(source)"
                  text: "$(content)"
              response:
                block: "$(resp.block)"
                block_message: "$(resp.block_message)"
              metrics:
                block_reason: "$(resp.block_reason)"
                block_details: "$(resp.audit_hash)"

  # Kong `ai-mcp-proxy` documents `AI Guardrails: supported: false` on MCP routes.
  # Routing `passthrough-listener` to `adom mcp-http` preserves Kong AuthN/ACLs/OTel
  # while adding ADOM per-argument taint, capability tiers, SSRF IP-pinning, and ChainLog.
  - name: governed-mcp-service
    url: {adom_mcp_upstream_url}
    routes:
      - name: mcp-governed-route
        paths:
          - /mcp/v1
        plugins:
          - name: key-auth
          - name: ai-mcp-proxy
            config:
              mode: passthrough-listener
              logging:
                log_audits: true
'''
