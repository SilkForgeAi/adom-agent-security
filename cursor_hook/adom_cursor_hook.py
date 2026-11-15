#!/usr/bin/env python3
"""ADOM in front of Cursor — hook bridge (v0.4).

Cursor runs this script before shell commands, MCP tool calls and file reads.
It passes the action to ADOM's existing policy (adom.enforcement.action_kernel
.screen_action + adom.api.model_proxy.ModelProxyPolicy) and returns ADOM's verdict.

Modes (env ADOM_MODE, default "observe"):
  observe  -> always ALLOW, but log what ADOM *would* have decided.
  enforce  -> return ADOM's verdict to Cursor (block = deny, exit code 2).

Every decision is appended to ~/.adom/cursor/decisions.jsonl as a SHA-256 hash chain
(each record includes the hash of the previous one). The log lives outside the
iCloud-synced Desktop on purpose.

v0.1 limits (stated honestly):
  - Stateless: each hook call is a fresh process, so ADOM's session tracking
    (read-then-send chains, learned secrets) does not carry across calls yet.
  - Only actions Cursor exposes through hooks are seen.

v0.2 adds coding-agent checks (adom_cursor_checks.py): self-protection of ADOM's own
files, package lookalike detection on installs, and credentials written into source.
v0.3 replaces ADOM's allowlist-only shell rule with adom_cursor_shell.py (developer
default-allow + ADOM escape/privilege signatures); the core verdict is still logged.
v0.5 routes reads, MCP calls and agent tools through adom.enforcement.action_tiers.
Since the Oct 11 kernel hardening, an ungranted tool always fails closed, so every
file read and MCP call was denied in enforce mode. Tiers decide what grant the kernel
gets: built-in reads are allowed, credential stores and persistence writes are denied,
unknown MCP tools are denied until a person classifies them in ~/.adom/tool_tiers.json,
and registry-granted MCP tools are screened by the kernel with an exact grant.
"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

ADOM_ROOT = Path(__file__).resolve().parent.parent          # .../ADOM
sys.path.insert(0, str(ADOM_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

LOG_DIR = Path.home() / ".adom" / "cursor"
LOG_FILE = LOG_DIR / "decisions.jsonl"
_RAW_MODE = os.environ.get("ADOM_MODE", "").strip().lower()
# Fail closed on unrecognized non-empty ADOM_MODE values (typos never silently become observe).
MODE = "observe" if _RAW_MODE in ("", "observe") else "enforce"
ANCHOR_FILE = os.environ.get("ADOM_AUDIT_ANCHOR_PATH") or ""

# Events that ask for a permission decision, and the reply shape Cursor expects.
GATED = {"beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "preToolUse"}


def _last_hash():
    try:
        with open(LOG_FILE, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 65536))
            lines = f.read().splitlines()
        return json.loads(lines[-1])["hash"] if lines else "0" * 64
    except Exception:
        return "0" * 64


def _log(record):
    """Append one record to the hash chain.

    Cursor runs hooks in parallel, so reading the last hash and appending must be one
    atomic step. Without the lock, two hooks can read the same last hash and fork the
    chain (observed: 8 forks in 30 parallel calls)."""
    import fcntl
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(LOG_DIR, 0o700)
    with open(LOG_DIR / ".lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)             # released when the file closes
        record["prev_hash"] = _last_hash()
        body = json.dumps(record, sort_keys=True, separators=(",", ":"))
        record["hash"] = hashlib.sha256((record["prev_hash"] + body).encode()).hexdigest()
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        if ANCHOR_FILE:
            try:
                count = sum(1 for _ in open(LOG_FILE, "rb"))
                ap = Path(ANCHOR_FILE)
                ap.parent.mkdir(parents=True, exist_ok=True)
                tmp = ap.with_suffix(ap.suffix + ".tmp")
                tmp.write_text(f"{count}:{record['hash']}\n")
                os.replace(tmp, ap)
            except Exception:
                if MODE == "enforce":
                    raise


def _to_action(event, payload):
    """Map a Cursor hook payload onto ADOM's (tool name, args) shape."""
    if event == "beforeShellExecution":
        return "run_shell_command", {"command": payload.get("command", ""),
                                     "cwd": payload.get("cwd", "")}
    if event == "beforeMCPExecution":
        raw = payload.get("tool_input", {})
        try:
            args = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError:
            args = {"raw": raw}
        tool = str(payload.get("tool_name", "unknown"))
        # Claude Code names are already namespaced (mcp__server__tool); Cursor's are bare.
        return (tool if tool.startswith("mcp__") else "mcp:" + tool), args
    if event == "beforeReadFile":
        return "read_file", {"path": payload.get("file_path", "")}
    if event == "preToolUse":
        return str(payload.get("tool_name", "unknown")), payload.get("tool_input", {})
    return event, {}


def _reply(event, allow, reason):
    if event == "beforeSubmitPrompt":
        return {"continue": True}
    if event not in GATED:
        return {}
    out = {"permission": "allow" if allow else "deny"}
    if not allow:
        out["user_message"] = "ADOM blocked this action: " + reason
        out["agent_message"] = "This action was blocked by ADOM policy: " + reason
    return out


_QUIET_PRETOOL = {"shell", "read", "grep", "glob", "ls", "list", "search",
                  "codebase_search", "semanticsearch", "filesearch", "task"}


_AGENT_CONFIG = {                      # agent -> (baseline key, health function name, label)
    "cursor": ("hooks_json_sha256", "config_health", "~/.cursor/hooks.json"),
    "claude_code": ("claude_settings_sha256", "claude_config_health", "~/.claude/settings.json"),
}


def evaluate(payload, agent="cursor", mode=None):
    """Decide on one agent action and write it to the hash chain.

    `payload` is in Cursor's hook shape (other agents' adapters translate to it).
    Returns {"event", "allow", "reason", "logged"}. Shared by every agent adapter so
    policy, checks and audit trail are identical across agents."""
    mode = (mode or MODE)
    started = time.perf_counter()
    event, name, verdict, reason, signals, subject = "unknown", "", "error", "", [], ""
    findings, config, core, tier_log = [], None, None, {}
    try:
        event = payload.get("hook_event_name") or "unknown"
        import adom_cursor_checks as checks
        import adom_cursor_health as health
        from adom.enforcement import action_tiers as tiers
        tier_agent = "claude_code" if payload.get("_adom_agent") == "claude_code" else "cursor"
        if event == "preToolUse" and str(payload.get("tool_name", "")).lower() in _QUIET_PRETOOL:
            # Covered by the shell / read hooks; don't double-log - unless the tier layer
            # objects (e.g. Grep over ~/.ssh), in which case it is decided below.
            qc = tiers.classify(str(payload.get("tool_name", "")), payload.get("tool_input") or {},
                                tier_agent, str(payload.get("cwd") or ""))
            if tiers.decide(qc).action != tiers.BLOCK:
                return {"event": event, "allow": True, "reason": "", "logged": False}
        findings = checks.run_all(event, payload)
        key, health_fn, label = _AGENT_CONFIG.get(agent, _AGENT_CONFIG["cursor"])
        config = health.baseline_status(key)["state"]
        if config == "changed":
            findings.append({"check": "self_protection", "action": "flag",
                             "reason": f"TAMPER ALERT: {label} differs from trusted baseline"})
        h = getattr(health, health_fn)()
        if h["status"] != "ok":
            findings.append({"check": "self_protection", "action": "flag",
                             "reason": f"{label} health {h['status']}: " + h["issues"][0][1]})
        if event not in GATED:                       # observational events: record findings
            _log({"ts": time.time(), "agent": agent, "event": event, "mode": mode,
                  "config": config, "subject": str(payload.get("file_path") or "")[:300],
                  "findings": findings,
                  "conversation_id": payload.get("conversation_id")})
            return {"event": event, "allow": True, "reason": "", "logged": True}
        name, args = _to_action(event, payload)
        subject = str(payload.get("command") or payload.get("file_path")
                      or payload.get("tool_name") or "")[:300]
        cwd = str(payload.get("cwd") or "")
        if event != "beforeShellExecution":
            tc = tiers.classify(name, args, tier_agent, cwd)
            td = tiers.decide(tc)
            tier_log = dict(tc.as_log(), tier_decision=td.action)
        if event == "preToolUse":
            verdict, reason = "allow", ""            # write/delete tools: ADOM checks below decide
            ti = payload.get("tool_input") or {}
            if isinstance(ti, dict):
                subject = str(ti.get("file_path") or ti.get("path") or ti.get("target_file")
                              or payload.get("tool_name") or "")[:300]
            if td.action == tiers.BLOCK:
                verdict, reason, signals = "block", td.reason, list(td.signals)
            else:
                signals = list(td.signals)
                if tc.tier == tiers.CONSEQUENTIAL:
                    from adom.api.model_proxy import _encoded_secret_hit, _ssrf_hit
                    raw_vals = tiers.strings(ti)
                    joined = "\n".join(raw_vals)
                    hit = _encoded_secret_hit(joined, ())
                    if hit:
                        verdict, reason = "block", f"'{name}' carries an encoded/obfuscated secret ({hit})"
                        signals.append("hook:encoded_secret_in_outbound")
                    else:
                        dest = ""
                        if isinstance(ti, dict):
                            dest = str(ti.get("url") or ti.get("uri") or ti.get("endpoint")
                                       or ti.get("target") or "")
                        if dest and _ssrf_hit(dest, None):
                            verdict, reason = "block", f"'{name}' targets an internal/metadata address (SSRF)"
                            signals.append("hook:ssrf_internal_target")
        elif event == "beforeShellExecution":
            # Coding-agent shell policy; ADOM's core verdict is kept for comparison.
            import adom_cursor_shell as shellpolicy
            from adom.api.model_proxy import ModelProxyPolicy, _privesc_hit, _ssrf_hit
            from adom.enforcement.egress_proxy import _SECRET_RX
            from adom.enforcement.action_kernel import screen_action
            cmd_str = payload.get("command", "")
            _, cv = screen_action(ModelProxyPolicy(), name, args)
            core = cv.action
            d = shellpolicy.decide(cmd_str)
            verdict, reason, signals = d["action"], d["reason"], list(d["signals"])
            cred = tiers.shell_credential_access(cmd_str)
            if verdict != "block" and cred:
                verdict = "block"
                reason = f"credential containment: command reads a credential store ({cred})"
                signals.append("tier:credential_store")
            if verdict != "block":
                sec = next((lbl for rx, lbl in _SECRET_RX if lbl != "credential_kv" and rx.search(cmd_str)), None)
                if sec:
                    verdict = "block"
                    reason = f"shell command contains a credential-shaped value ({sec})"
                    signals.append(f"hook:shell_secret:{sec}")
                elif _privesc_hit(name, cmd_str):
                    verdict = "block"
                    reason = "shell command attempts privilege escalation"
                    signals.append("hook:shell_privesc")
                elif ("http://" in cmd_str or "https://" in cmd_str) and _ssrf_hit(cmd_str, None):
                    verdict = "block"
                    reason = "shell command targets an internal/metadata address (SSRF)"
                    signals.append("hook:shell_ssrf")
        else:                                        # beforeReadFile, beforeMCPExecution
            signals = list(td.signals)
            if td.action == tiers.BLOCK:
                verdict, reason = "block", td.reason
            elif td.action == tiers.SCREEN:          # registry grant -> kernel decides
                confirmed = (False, "not needed")
                if tc.registry_entry is not None and tc.registry_entry.agent_approval:
                    import adom_agent_permissions as perms
                    confirmed = perms.prompt_confirmed(tier_agent, name, cwd,
                                                       payload.get("permission_mode"))
                from adom.enforcement import review
                contracts, approvals = review.load_local()   # raises -> denied below
                sd = tiers.screen(tc, args, confirmed, contracts=contracts,
                                  approvals=approvals, agent_id=tier_agent)
                verdict = "block" if sd.action == tiers.BLOCK else "allow"
                reason = sd.reason
                signals += list(sd.signals)
                tier_log["tier_decision"] = "screen:" + sd.action
            else:
                verdict, reason = "allow", ""
        blocking = [f for f in findings if f.get("action") == "block"]
        if blocking:                                 # coding-agent checks take priority
            verdict, reason = "block", blocking[0]["reason"]
    except Exception as exc:                          # fail closed in enforce mode
        verdict, reason, signals = "block", "ADOM hook error: " + type(exc).__name__, ["hook:error"]

    allow = True if mode != "enforce" else verdict != "block"
    logged = True
    try:
        _log({"ts": time.time(), "agent": agent, "event": event, "tool": name, "mode": mode,
              "subject": subject, "adom_verdict": verdict, "reason": reason, "signals": signals,
              "findings": findings, "config": config, "core_verdict": core,
              "returned": "allow" if allow else "deny", **tier_log,
              "latency_ms": round((time.perf_counter() - started) * 1000, 2)})
    except Exception:
        logged = False
        if mode == "enforce":
            allow, reason = False, "ADOM audit log unavailable"
    return {"event": event, "allow": allow, "reason": reason, "logged": logged}


def main():
    """Cursor entry point: stdin payload -> Cursor reply JSON on stdout, exit 2 on deny."""
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not payload.get("hook_event_name") and len(sys.argv) > 1:
            payload["hook_event_name"] = sys.argv[1]
    except Exception:
        payload = None
    if payload is None:                               # unreadable input: same as a hook error
        allow = MODE != "enforce"
        try:
            _log({"ts": time.time(), "agent": "cursor", "event": "unknown", "tool": "",
                  "mode": MODE, "subject": "", "adom_verdict": "block",
                  "reason": "ADOM hook error: JSONDecodeError", "signals": ["hook:error"],
                  "findings": [], "config": None, "core_verdict": None,
                  "returned": "allow" if allow else "deny", "latency_ms": 0.0})
        except Exception:
            pass
        print(json.dumps(_reply("unknown", allow, "ADOM hook error: JSONDecodeError")))
        return 0 if allow else 2
    r = evaluate(payload, "cursor")
    print(json.dumps(_reply(r["event"], r["allow"], r["reason"])))
    return 0 if r["allow"] else 2


if __name__ == "__main__":
    sys.exit(main())
