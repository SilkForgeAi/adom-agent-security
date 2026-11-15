#!/usr/bin/env python3
"""Install / switch / remove ADOM's hooks in Cursor's ~/.cursor/hooks.json.

  python3 adom-agent-security/cursor_hook/install_cursor_hooks.py observe   # install, log only
  python3 adom-agent-security/cursor_hook/install_cursor_hooks.py enforce   # install, block
  python3 adom-agent-security/cursor_hook/install_cursor_hooks.py remove    # take ADOM out

Keeps every non-ADOM hook and any other keys. Writes a timestamped backup first.
Refuses to touch a hooks.json that is not valid JSON (JSON has no comments).
Run by a human, not an agent. Restart Cursor afterwards.
"""
import json
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "adom_cursor_hook.py"
PYTHON = "/usr/bin/python3"
# event -> fail closed?  (afterFileEdit is observational; Cursor does not block on it)
EVENTS = {"beforeShellExecution": True, "beforeMCPExecution": True, "beforeReadFile": True,
          "preToolUse": True, "afterFileEdit": False}


def is_adom(h):
    return isinstance(h, dict) and "adom_cursor_hook.py" in str(h.get("command", ""))


def main(argv):
    mode = (argv[1] if len(argv) > 1 else "").lower()
    if mode not in ("observe", "enforce", "remove"):
        print(__doc__)
        return 1
    path = Path.home() / ".cursor" / "hooks.json"
    cfg = {"version": 1}
    if path.exists():
        try:
            cfg = json.loads(path.read_text())
        except ValueError as exc:
            print(f"hooks.json is not valid JSON ({exc}); not changing it.")
            return 1
        if not isinstance(cfg, dict):
            print("hooks.json top level is not an object; not changing it.")
            return 1
        backup = path.with_name(f"hooks.json.adom-backup-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)
        print(f"Backup: {backup}")
    cfg["version"] = 1
    hooks = cfg.get("hooks") if isinstance(cfg.get("hooks"), dict) else {}
    for ev in list(hooks):                          # drop old ADOM entries, keep everything else
        if isinstance(hooks[ev], list):
            hooks[ev] = [h for h in hooks[ev] if not is_adom(h)]
            if not hooks[ev]:
                del hooks[ev]
    if mode != "remove":
        prefix = "ADOM_MODE=enforce " if mode == "enforce" else ""
        cmd = f"{prefix}{PYTHON} {SCRIPT}"
        for ev, fail_closed in EVENTS.items():
            entry = {"command": cmd}
            if fail_closed:
                entry.update(failClosed=True, timeout=10)
            hooks.setdefault(ev, []).insert(0, entry)
    cfg["hooks"] = hooks
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.adom-tmp")
    tmp.write_text(json.dumps(cfg, indent=2) + "\n")
    tmp.replace(path)                               # atomic swap: never a half-written file
    print(f"ADOM hooks: {'removed' if mode == 'remove' else mode} in {path}")
    if mode != "remove":
        sys.path.insert(0, str(HERE))
        import adom_cursor_health as health
        h = health.config_health(path)
        print(f"health: {h['status'].upper()}  mode: {h['mode']}")
        for sev, text in h["issues"]:
            print(f"  {sev}: {text}")
    print("Next: restart Cursor, then python3 adom-agent-security/cursor_hook/watch.py --trust")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
