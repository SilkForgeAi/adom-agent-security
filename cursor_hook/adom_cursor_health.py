"""Health check for ~/.cursor/hooks.json (stdlib only, Python 3.9+).

The hash baseline answers "did hooks.json change?". This answers "is ADOM still
actually in front of Cursor?" - a file can be unchanged-since-trust and still be
broken, or be edited into something that parses but no longer runs ADOM.

Severity:
  broken  - ADOM is not (fully) in front of Cursor; fix before relying on it
  warning - ADOM runs, but weaker than intended (e.g. a crash would fail open)
"""
import json
import os
import re
from pathlib import Path

REQUIRED = {                       # event -> must it fail closed?
    "beforeShellExecution": True,
    "beforeMCPExecution": True,
    "beforeReadFile": True,
    "preToolUse": True,
    "afterFileEdit": False,        # observational: Cursor does not block on it
}
_SCRIPT_RX = re.compile(r"(\S*adom_cursor_hook\.py)")
_MODE_RX = re.compile(r"^\s*ADOM_MODE=(\w+)\s")


def _default_path():
    return Path.home() / ".cursor" / "hooks.json"


def config_health(path=None, check_files=True):
    """Return {"status": "ok"|"warning"|"broken", "mode": str, "issues": [(severity, text)]}."""
    p = Path(path) if path else _default_path()
    issues = []

    def bad(text):
        issues.append(("broken", text))

    def warn(text):
        issues.append(("warning", text))

    if not p.exists():
        bad(f"{p} does not exist - Cursor is running with no ADOM hooks")
        return _result(issues, "none")
    raw = p.read_text(errors="replace")
    try:
        cfg = json.loads(raw)
    except ValueError as exc:
        hint = " (JSON does not allow // or /* */ comments)" if re.search(r"^\s*(//|/\*)", raw, re.M) else ""
        bad(f"hooks.json is not valid JSON{hint}: {exc.msg} at line {exc.lineno} - "
            f"Cursor may load no hooks at all")
        return _result(issues, "unknown")
    if not isinstance(cfg, dict):
        bad("hooks.json top level is not an object")
        return _result(issues, "unknown")
    if cfg.get("version") != 1:
        bad(f"hooks.json version is {cfg.get('version')!r}, Cursor requires 1")
    hooks = cfg.get("hooks")
    if not isinstance(hooks, dict):
        bad("hooks.json has no 'hooks' object")
        return _result(issues, "unknown")

    modes = set()
    for event, must_fail_closed in REQUIRED.items():
        entries = hooks.get(event)
        if not isinstance(entries, list):
            bad(f"{event}: missing - ADOM does not see these actions")
            continue
        adom = [e for e in entries if isinstance(e, dict)
                and _SCRIPT_RX.search(str(e.get("command", "")))]
        if not adom:
            bad(f"{event}: present, but no entry runs adom_cursor_hook.py")
            continue
        e = adom[0]
        cmd = str(e.get("command", ""))
        m = _MODE_RX.match(cmd)
        modes.add(m.group(1).lower() if m else "observe")
        if must_fail_closed and e.get("failClosed") is not True:
            warn(f"{event}: failClosed is not true - if ADOM crashes or times out, "
                 f"Cursor lets the action through")
        if e.get("matcher"):
            warn(f"{event}: has matcher {e['matcher']!r} - ADOM only sees matching actions")
        if e.get("type", "command") != "command":
            bad(f"{event}: type is {e.get('type')!r}, ADOM needs 'command'")
        if check_files:
            script = os.path.expanduser(_SCRIPT_RX.search(cmd).group(1))
            if not os.path.isfile(script):
                bad(f"{event}: hook script not found at {script}")
            interp = next((t for t in cmd.split() if t.startswith("/") and "python" in t), None)
            if interp and not os.path.exists(interp):
                bad(f"{event}: interpreter {interp} not found - with failClosed every action is blocked")

    mode = modes.pop() if len(modes) == 1 else ("mixed" if modes else "none")
    if mode == "mixed":
        warn("hooks use different ADOM_MODE values - some enforce, some only observe")
    return _result(issues, mode)


def _result(issues, mode):
    sev = {s for s, _ in issues}
    status = "broken" if "broken" in sev else ("warning" if "warning" in sev else "ok")
    return {"status": status, "mode": mode, "issues": issues}


# ---------------------------------------------------------------- trust baselines (all agents)
def _home():
    return Path.home()


def watched_files():
    """Config files whose content decides whether ADOM runs, keyed by baseline field."""
    return {"hooks_json_sha256": _home() / ".cursor" / "hooks.json",
            "claude_settings_sha256": _home() / ".claude" / "settings.json"}


def baseline_file():
    return _home() / ".adom" / "cursor" / "trusted_config.json"


def _sha(path):
    import hashlib
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def fingerprint(key):
    """What the trust baseline covers for one watched file.

    Cursor's hooks.json holds only hooks, so the whole file is fingerprinted.
    Claude Code's settings.json also holds theme, model and other preferences that Claude
    Code rewrites on its own, so only its "hooks" section is fingerprinted (canonical JSON).
    If the file cannot be parsed, the raw bytes are fingerprinted, so a broken file still
    shows up as changed."""
    path = watched_files()[key]
    if key != "claude_settings_sha256":
        return _sha(path)
    import hashlib
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    try:
        cfg = json.loads(raw)
        hooks = cfg.get("hooks") if isinstance(cfg, dict) else None
        canon = json.dumps({"hooks": hooks}, sort_keys=True, separators=(",", ":"))
        return "hooks:" + hashlib.sha256(canon.encode()).hexdigest()
    except ValueError:
        return hashlib.sha256(raw).hexdigest()


def baseline_status(key):
    """trusted | changed | missing | no_baseline for one watched file."""
    current = fingerprint(key)
    try:
        baseline = json.loads(baseline_file().read_text()).get(key)
    except (OSError, ValueError):
        baseline = None
    if baseline is None:
        return {"state": "no_baseline", "current": current, "baseline": None}
    if current is None:
        return {"state": "missing", "current": None, "baseline": baseline}
    return {"state": "trusted" if current == baseline else "changed",
            "current": current, "baseline": baseline}


def trust_all():
    """Record the current content of every watched file that exists as trusted."""
    bf = baseline_file()
    bf.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(bf.parent, 0o700)
    data = {k: fingerprint(k) for k, p in watched_files().items() if Path(p).exists()}
    bf.write_text(json.dumps(data) + "\n")
    os.chmod(bf, 0o600)
    return data


# ---------------------------------------------------------------- Claude Code settings health
_CLAUDE_SCRIPT_RX = re.compile(r"(\S*adom_claude_hook\.py)")


def claude_config_health(path=None, check_files=True):
    """Is ADOM in front of Claude Code?  Reads ~/.claude/settings.json.

    Note: Claude Code hooks fail open by design (timeouts, crashes and missing scripts do
    not block). That is a platform property, reported in the README, not per-config."""
    p = Path(path) if path else _home() / ".claude" / "settings.json"
    issues = []
    if not p.exists():
        return _result([("broken", f"{p} does not exist - no ADOM hooks for Claude Code")], "none")
    try:
        cfg = json.loads(p.read_text(errors="replace"))
    except ValueError as exc:
        return _result([("broken", f"settings.json is not valid JSON: {exc.msg} at line "
                                   f"{exc.lineno} - Claude Code may ignore it")], "unknown")
    hooks = cfg.get("hooks") if isinstance(cfg, dict) else None
    if not isinstance(hooks, dict):
        return _result([("broken", "settings.json has no 'hooks' object")], "none")
    modes = set()
    for event, required in (("PreToolUse", True), ("PostToolUse", False)):
        groups = hooks.get(event) if isinstance(hooks.get(event), list) else []
        found = None
        for g in groups:
            for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                if isinstance(h, dict) and _CLAUDE_SCRIPT_RX.search(str(h.get("command", ""))):
                    found = (g, h)
                    break
            if found:
                break
        if not found:
            (issues.append(("broken" if required else "warning",
                            f"{event}: no hook runs adom_claude_hook.py"
                            + (" - ADOM does not see Claude Code's actions" if required
                               else " - after-the-fact edit alerts are off"))))
            continue
        g, h = found
        m = str(g.get("matcher", "") or "")
        if m not in ("", "*"):
            issues.append(("warning", f"{event}: matcher {m!r} - ADOM only sees matching tools"))
        if h.get("if"):
            issues.append(("warning", f"{event}: 'if' condition narrows which calls ADOM sees"))
        if h.get("async") or h.get("asyncRewake"):
            issues.append(("broken" if required else "warning",
                           f"{event}: hook is async - it cannot block"))
        cmd = str(h.get("command", ""))
        mm = _MODE_RX.match(cmd)
        modes.add(mm.group(1).lower() if mm else "observe")
        if check_files:
            script = os.path.expanduser(_CLAUDE_SCRIPT_RX.search(cmd).group(1))
            if not os.path.isfile(script):
                issues.append(("broken", f"{event}: hook script not found at {script}"))
            interp = next((t for t in cmd.split() if t.startswith("/") and "python" in t), None)
            if interp and not os.path.exists(interp):
                issues.append(("broken", f"{event}: interpreter {interp} not found"))
    mode = modes.pop() if len(modes) == 1 else ("mixed" if modes else "none")
    if mode == "mixed":
        issues.append(("warning", "hooks use different ADOM_MODE values"))
    return _result(issues, mode)
