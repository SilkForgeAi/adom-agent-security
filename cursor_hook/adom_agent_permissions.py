"""Can ADOM confirm a person will actually see the agent's approval prompt? (v0.5)

Used only for registry entries that set "agent_approval": true. That opt-in lets the
agent's own approval prompt count as the review ADOM's kernel requires for outbound
actions. It is only safe when the prompt really appears, so this module checks the
agent's own permission settings and answers conservatively: if anything is unreadable
or unknown, the answer is "not confirmed" and ADOM blocks.

Claude Code (supported):
  * permission_mode "bypassPermissions" in the hook payload (--dangerously-skip-permissions)
    or permissions.defaultMode "bypassPermissions" in any settings file -> no prompt.
  * The tool matches a permissions.allow rule (exact name, the bare server "mcp__srv",
    or a glob such as "mcp__srv__*") in any settings file and no "ask" rule -> no prompt.
    "Yes, and don't ask again" writes such an allow rule to .claude/settings.local.json.
  Settings files checked: managed settings, ~/.claude/settings.json,
  ~/.claude/settings.local.json, <cwd>/.claude/settings.json,
  <cwd>/.claude/settings.local.json.

Cursor: no stable, documented place to read its auto-run state, so the prompt can never be
confirmed and agent_approval is not honored for Cursor (ADOM blocks).
"""
import fnmatch
import json
from pathlib import Path
from typing import List, Optional, Tuple

MANAGED = [Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
           Path("/etc/claude-code/managed-settings.json")]


def _settings_files(cwd: str) -> List[Path]:
    home = Path.home()
    files = list(MANAGED) + [home / ".claude" / "settings.json",
                             home / ".claude" / "settings.local.json"]
    if cwd:
        files += [Path(cwd) / ".claude" / "settings.json",
                  Path(cwd) / ".claude" / "settings.local.json"]
    return files


def _matches(rule: str, tool: str) -> bool:
    rule = str(rule or "").strip()
    if not rule:
        return False
    if "(" in rule:                                   # argument-scoped rules, e.g. Bash(npm test)
        base = rule.split("(", 1)[0]
        return base == tool and rule.endswith("(*)")
    if rule == tool or fnmatch.fnmatchcase(tool, rule):
        return True
    # A bare server rule "mcp__srv" allows every tool of that server.
    return rule.startswith("mcp__") and rule.count("__") == 1 and tool.startswith(rule + "__")


def claude_prompt_confirmed(tool: str, cwd: str = "",
                            permission_mode: Optional[str] = None) -> Tuple[bool, str]:
    """(True, "") only if every readable signal says Claude Code will prompt for `tool`."""
    if permission_mode == "bypassPermissions":
        return False, "Claude Code is running with permissions bypassed"
    allow_hit, ask_hit = None, None
    for f in _settings_files(cwd):
        if not f.exists():
            continue
        try:
            data = json.loads(f.read_text())
        except (OSError, ValueError):
            return False, f"cannot read {f} to confirm the approval prompt"
        perms = data.get("permissions") if isinstance(data, dict) else None
        if perms is None:
            continue
        if not isinstance(perms, dict):
            return False, f"unexpected permissions block in {f}"
        if perms.get("defaultMode") == "bypassPermissions":
            return False, f"defaultMode bypassPermissions in {f}"
        for rule in perms.get("ask") or []:
            if _matches(rule, tool):
                ask_hit = f"{rule} ({f})"
        for rule in perms.get("allow") or []:
            if _matches(rule, tool):
                allow_hit = f"{rule} ({f})"
    if allow_hit and not ask_hit:
        return False, f"'{tool}' is auto-allowed by {allow_hit}, so no one sees a prompt"
    return True, ""


def prompt_confirmed(agent: str, tool: str, cwd: str = "",
                     permission_mode: Optional[str] = None) -> Tuple[bool, str]:
    if agent == "claude_code":
        return claude_prompt_confirmed(tool, cwd, permission_mode)
    return False, f"cannot confirm {agent}'s approval prompt is shown"
