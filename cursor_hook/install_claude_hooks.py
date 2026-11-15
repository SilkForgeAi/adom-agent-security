#!/usr/bin/env python3
"""Install / switch / remove ADOM's hooks in Claude Code's ~/.claude/settings.json.

  python3 adom-agent-security/cursor_hook/install_claude_hooks.py observe   # install, log only
  python3 adom-agent-security/cursor_hook/install_claude_hooks.py enforce   # install, block
  python3 adom-agent-security/cursor_hook/install_claude_hooks.py remove    # take ADOM out

Keeps every other setting and every non-ADOM hook. Writes a timestamped backup first.
Refuses to touch a settings.json that is not valid JSON. Run by a human, not an agent.
"""
import json
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "adom_claude_hook.py"
PYTHON = "/usr/bin/python3"
EVENTS = ("PreToolUse", "PostToolUse")


def is_adom(h):
    return isinstance(h, dict) and "adom_claude_hook.py" in str(h.get("command", ""))


def main(argv):
    mode = (argv[1] if len(argv) > 1 else "").lower()
    if mode not in ("observe", "enforce", "remove"):
        print(__doc__)
        return 1
    path = Path.home() / ".claude" / "settings.json"
    cfg = {}
    if path.exists():
        try:
            cfg = json.loads(path.read_text())
        except ValueError as exc:
            print(f"settings.json is not valid JSON ({exc}); not changing it.")
            return 1
        if not isinstance(cfg, dict):
            print("settings.json top level is not an object; not changing it.")
            return 1
        backup = path.with_name(f"settings.json.adom-backup-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)
        print(f"Backup: {backup}")
    hooks = cfg.setdefault("hooks", {})
    for ev in EVENTS:                              # drop old ADOM entries, keep everything else
        groups = [g for g in hooks.get(ev, []) if isinstance(g, dict)]
        for g in groups:
            g["hooks"] = [h for h in (g.get("hooks") or []) if not is_adom(h)]
        hooks[ev] = [g for g in groups if g.get("hooks")]
        if not hooks[ev]:
            del hooks[ev]
    if mode != "remove":
        prefix = "ADOM_MODE=enforce " if mode == "enforce" else ""
        cmd = f"{prefix}{PYTHON} {SCRIPT}"
        for ev in EVENTS:
            hooks.setdefault(ev, []).append(
                {"matcher": "*", "hooks": [{"type": "command", "command": cmd, "timeout": 10}]})
    if not hooks:
        del cfg["hooks"]
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.adom-tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n")
    tmp.replace(path)                              # atomic swap: never a half-written file
    print(f"ADOM hooks: {'removed' if mode == 'remove' else mode} in {path}")
    if mode != "remove":
        sys.path.insert(0, str(HERE))
        import adom_cursor_health as health
        h = health.claude_config_health(path)
        print(f"health: {h['status'].upper()}  mode: {h['mode']}")
        for sev, text in h["issues"]:
            print(f"  {sev}: {text}")
    print("Next: python3 adom-agent-security/cursor_hook/watch.py --trust   (review, then trust)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
