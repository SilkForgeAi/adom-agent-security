#!/usr/bin/env python3
"""Unified offline fail-closed coding-agent hook bridge for ADOM.

Supports:
  - cursor
  - claude-code
  - codex
  - github-copilot

Every client routes into shared offline deterministic checks and
``adom_cursor_hook.evaluate`` (zero network calls, fail-closed in enforce mode,
hash-chained JSONL audit log).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adom_claude_hook as claude_adapter  # noqa: E402
import adom_cursor_hook as engine  # noqa: E402

_SHELL_TOOLS = {"shell", "bash", "run_in_terminal", "local_shell", "execute_command", "terminal"}
_READ_TOOLS = {"read", "read_file", "view_file", "open_file"}


def _translate_generic(client: str, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Translate Codex / GitHub Copilot hook JSON onto ADOM's shared event payload."""
    tool = str(raw.get("tool_name") or raw.get("toolName") or raw.get("tool") or "").strip()
    tool_lower = tool.lower()
    ti = raw.get("tool_input") if isinstance(raw.get("tool_input"), dict) else raw.get("toolArgs")
    if isinstance(ti, str):
        try:
            ti = json.loads(ti)
        except ValueError:
            ti = {"raw": ti}
    if not isinstance(ti, dict):
        ti = {}
    cwd = str(raw.get("cwd") or "")
    base: Dict[str, Any] = {
        "_adom_agent": client.replace("-", "_"),
        "conversation_id": raw.get("session_id") or raw.get("conversation_id") or raw.get("sessionId"),
        "cwd": cwd,
        "permission_mode": raw.get("permission_mode"),
    }
    if tool_lower in _SHELL_TOOLS or ("command" in raw and not tool):
        cmd = str(ti.get("command") or ti.get("cmd") or raw.get("command") or "")
        return dict(base, hook_event_name="beforeShellExecution", command=cmd)
    if tool_lower in _READ_TOOLS:
        fp = str(ti.get("file_path") or ti.get("path") or raw.get("file_path") or "")
        return dict(base, hook_event_name="beforeReadFile", file_path=claude_adapter._abs(fp, cwd))
    if tool_lower.startswith("mcp__") or tool_lower.startswith("mcp:"):
        return dict(base, hook_event_name="beforeMCPExecution", tool_name=tool, tool_input=ti)
    if raw.get("hook_event_name"):
        return dict(base, **raw)
    if tool:
        return dict(base, hook_event_name="preToolUse", tool_name=tool, tool_input=ti)
    return None


def _format_reply(client: str, allow: bool, reason: str, event: str) -> tuple[int, str]:
    if client == "claude-code":
        if allow:
            return 0, ""
        sys.stderr.write("ADOM blocked this action: " + (reason or "policy") + "\n")
        return 2, ""
    if client in ("codex", "github-copilot"):
        decision = "allow" if allow else "deny"
        payload = {"permissionDecision": decision} if client == "github-copilot" else {"decision": "allow" if allow else "block"}
        if not allow:
            msg = "ADOM blocked this action: " + (reason or "policy")
            payload["permissionDecisionReason" if client == "github-copilot" else "reason"] = msg
        return (0 if allow else 2), json.dumps(payload)
    # cursor
    return (0 if allow else 2), json.dumps(engine._reply(event, allow, reason))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="adom_agent_hook")
    ap.add_argument("--client", required=True, choices=("cursor", "claude-code", "codex", "github-copilot"))
    opts = ap.parse_args(argv)
    mode = engine.MODE

    try:
        raw_text = sys.stdin.read() or "{}"
        raw = json.loads(raw_text)
        if not isinstance(raw, dict):
            raise ValueError("hook payload must be a JSON object")
    except Exception as exc:
        allow = mode != "enforce"
        code, body = _format_reply(opts.client, allow, f"ADOM hook error: {type(exc).__name__}", "unknown")
        if body:
            print(body)
        return code

    if opts.client == "cursor":
        payload: Optional[Dict[str, Any]] = raw
    elif opts.client == "claude-code":
        payload = claude_adapter.translate(raw)
    else:
        payload = _translate_generic(opts.client, raw)

    if payload is None:
        # Known Claude Code events ADOM does not gate (PostToolUse after a non-write tool,
        # Stop, SessionStart, ...) get "no opinion". Blocking them does not stop anything;
        # on PostToolUse it tells the agent a finished action was blocked.
        if opts.client == "claude-code" and claude_adapter.is_ungated(raw):
            return 0
        # Unrecognized shapes must not fail open in enforce mode (same class of bug ADOM
        # reports in third-party hooks). Observe mode still allows and logs nothing here.
        if mode == "enforce":
            code, body = _format_reply(
                opts.client,
                False,
                "ADOM blocked unrecognized hook payload (fail-closed)",
                "unknown",
            )
            if body:
                print(body)
            return code
        return 0

    res = engine.evaluate(payload, opts.client.replace("-", "_"))
    code, body = _format_reply(opts.client, res["allow"], res["reason"], res["event"])
    if body:
        print(body)
    return code


if __name__ == "__main__":
    sys.exit(main())
