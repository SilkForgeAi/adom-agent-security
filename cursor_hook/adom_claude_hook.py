#!/usr/bin/env python3
"""ADOM in front of Claude Code - hook adapter (v0.4).

Claude Code runs this on PreToolUse (can block) and PostToolUse (after the fact).
It translates Claude Code's hook payload into the shape the shared ADOM engine uses
(adom_cursor_hook.evaluate), so policy, checks and the hash-chained audit log are
identical to the Cursor integration. Records carry "agent": "claude_code".

Replies, per Claude Code's hook contract:
  allow -> exit 0 with no output ("no opinion": Claude Code's own permission
           prompts still apply; ADOM never grants permission, it only denies)
  deny  -> exit 2, reason on stderr (Claude Code blocks the tool call and shows
           the reason to Claude)

Platform limit, stated plainly: Claude Code hooks fail OPEN. If this script cannot
start, crashes before replying, or exceeds its timeout, the action proceeds. There is
no failClosed setting. The engine itself denies on internal errors in enforce mode.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adom_cursor_hook as engine  # noqa: E402

_WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
_PATH_KEYS = ("file_path", "path", "notebook_path")

# Claude Code events ADOM deliberately has no opinion on. PreToolUse is the only event that
# can stop an action before it runs; PostToolUse fires after the tool already ran (ADOM only
# inspects it for file writes); the rest are lifecycle notices. Exiting 2 on these does not
# block anything: on PostToolUse it tells Claude a completed action was "blocked", which makes
# it retry. They are listed explicitly so an event name ADOM has never seen (for example a
# renamed PreToolUse) still fails closed in enforce mode instead of silently passing.
UNGATED_EVENTS = frozenset({
    "PostToolUse", "PostToolUseFailure", "Notification", "UserPromptSubmit", "Stop",
    "SubagentStart", "SubagentStop", "PreCompact", "SessionStart", "SessionEnd",
})


def is_ungated(cc):
    """True when the payload is a known Claude Code event that ADOM does not gate."""
    if not isinstance(cc, dict):
        return False
    ev = cc.get("hook_event_name")
    if ev not in UNGATED_EVENTS:
        return False
    # A PostToolUse for a write tool is inspected (translate() returns a payload for it).
    return not (ev == "PostToolUse" and str(cc.get("tool_name") or "") in _WRITE_TOOLS)
_NON_CONTENT_KEYS = set(_PATH_KEYS) | {"description", "start_line", "end_line",
                                       "old_string", "old_text", "replace_all", "cell_id",
                                       "cell_type", "edit_mode"}


def _abs(p, cwd):
    p = os.path.expanduser(str(p or ""))
    if p and not os.path.isabs(p) and cwd:
        p = os.path.join(cwd, p)
    return p


def _content_strings(obj, out):
    """New text an edit/write puts into a file (old text and metadata excluded)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _NON_CONTENT_KEYS:
                continue
            _content_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _content_strings(v, out)
    elif isinstance(obj, str):
        out.append(obj)


def translate(cc):
    """Claude Code payload -> shared-engine payload, or None if ADOM has nothing to do."""
    ev = cc.get("hook_event_name")
    tool = str(cc.get("tool_name") or "")
    ti = cc.get("tool_input") if isinstance(cc.get("tool_input"), dict) else {}
    cwd = str(cc.get("cwd") or "")
    base = {"_adom_agent": "claude_code", "conversation_id": cc.get("session_id"), "cwd": cwd,
            "permission_mode": cc.get("permission_mode")}
    if ev == "PreToolUse":
        if tool == "Bash":
            return dict(base, hook_event_name="beforeShellExecution",
                        command=str(ti.get("command") or ""))
        if tool == "Read":
            return dict(base, hook_event_name="beforeReadFile",
                        file_path=_abs(ti.get("file_path"), cwd))
        if tool.startswith("mcp__"):
            return dict(base, hook_event_name="beforeMCPExecution", tool_name=tool,
                        tool_input=ti)
        ti2 = dict(ti)
        for k in _PATH_KEYS:
            if ti2.get(k):
                ti2[k] = _abs(ti2[k], cwd)
        return dict(base, hook_event_name="preToolUse", tool_name=tool, tool_input=ti2)
    if ev == "PostToolUse" and tool in _WRITE_TOOLS:
        path = next((ti.get(k) for k in _PATH_KEYS if ti.get(k)), "")
        texts = []
        _content_strings(ti, texts)
        return dict(base, hook_event_name="afterFileEdit", file_path=_abs(path, cwd),
                    edits=[{"old_string": "", "new_string": t} for t in texts])
    return None


def main():
    try:
        cc = json.loads(sys.stdin.read() or "{}")
        payload = translate(cc)
    except Exception:
        if engine.MODE == "enforce":
            sys.stderr.write("ADOM blocked this action: hook input could not be read\n")
            return 2
        return 0
    if payload is None:
        if is_ungated(cc):
            return 0                     # known event ADOM has no opinion on (see UNGATED_EVENTS)
        # Anything else ADOM cannot place (no event name, an unknown event) fails closed.
        if engine.MODE == "enforce":
            sys.stderr.write("ADOM blocked this action: unrecognized hook payload\n")
            return 2
        return 0
    r = engine.evaluate(payload, "claude_code")
    if r["allow"]:
        return 0
    sys.stderr.write("ADOM blocked this action: " + (r["reason"] or "policy") + "\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
