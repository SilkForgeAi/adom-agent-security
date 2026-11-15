#!/usr/bin/env python3
"""Live view of ADOM's decisions on Cursor actions.

Usage:
  python3 adom-agent-security/cursor_hook/watch.py            follow live
  python3 adom-agent-security/cursor_hook/watch.py --summary  totals, config state, chain check
  python3 adom-agent-security/cursor_hook/watch.py --rotate   archive the current log, start a new chain
  python3 adom-agent-security/cursor_hook/watch.py --unclassified
                                                          MCP tools ADOM denied as unclassified,
                                                          with proposed tiers to review
  python3 adom-agent-security/cursor_hook/watch.py --trust    record the CURRENT ~/.cursor/hooks.json
                                                          as trusted (run only after you have
                                                          checked it yourself)
"""
import hashlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adom_cursor_health as health  # noqa: E402  (stdlib only)

LOG = Path.home() / ".adom" / "cursor" / "decisions.jsonl"
HOOKS_JSON = Path.home() / ".cursor" / "hooks.json"
BASELINE = Path.home() / ".adom" / "cursor" / "trusted_config.json"
RED, GREEN, YELLOW, GREY, BOLD, END = ("\033[31m", "\033[32m", "\033[33m", "\033[90m",
                                       "\033[1m", "\033[0m")
LABEL = {"self_protection": "SELF-PROTECT", "package_lookalike": "TYPOSQUAT",
         "secret_in_code": "SECRET-IN-CODE"}


AGENTS = [  # label, baseline key, health function, config file
    ("Cursor", "hooks_json_sha256", "config_health", Path.home() / ".cursor" / "hooks.json"),
    ("Claude Code", "claude_settings_sha256", "claude_config_health",
     Path.home() / ".claude" / "settings.json"),
]


def _active_agents():
    """Agents whose config file exists or that have a trusted baseline."""
    out = []
    for label, key, fn, path in AGENTS:
        st = health.baseline_status(key)
        if path.exists() or st["baseline"] is not None:
            out.append((label, key, fn, path))
    return out


def config_banner(state, label="hooks.json"):
    if state == "trusted":
        return f"{GREEN}{label}: trusted{END}"
    if state == "no_baseline":
        return f"{YELLOW}{label}: no trusted baseline yet (run watch.py --trust){END}"
    if state == "missing":
        return f"{RED}{BOLD}TAMPER ALERT: {label} is MISSING - ADOM is not in front of this agent{END}"
    return f"{RED}{BOLD}TAMPER ALERT: {label} CHANGED since you trusted it{END}"


def status_lines():
    """Trust + health lines for every active agent, and a key for change detection."""
    lines, key = [], []
    for label, bkey, fn, path in _active_agents():
        st = health.baseline_status(bkey)["state"]
        h = getattr(health, fn)()
        lines.append(f"{BOLD}{label}{END}  " + config_banner(st, path.name if label == "Cursor"
                                                          else "settings.json"))
        lines += ["  " + l for l in health_lines(h)]
        key.append((label, st, h["status"], tuple(h["issues"]), h["mode"]))
    return lines, tuple(key)


def health_lines(h=None):
    h = h or health.config_health()
    colour = {"ok": GREEN, "warning": YELLOW, "broken": RED + BOLD}[h["status"]]
    lines = [f"{colour}health: {h['status'].upper()}{END}   ADOM mode: {h['mode']}"]
    for sev, text in h["issues"]:
        lines.append(f"    {RED if sev == 'broken' else YELLOW}{sev}: {text}{END}")
    return lines


def detail(r):
    return (r.get("subject") or r.get("tool") or r.get("event", ""))[:60]


def show(r):
    t = time.strftime("%H:%M:%S", time.localtime(r.get("ts", 0)))
    t += " " + ("CC" if r.get("agent") == "claude_code" else "CU")   # Claude Code / Cursor
    findings = r.get("findings") or []
    for f in findings:                                   # new coding-agent checks first
        colour = RED if f.get("action") == "block" else YELLOW
        print(f"{t}  {colour}{BOLD}{LABEL.get(f.get('check'), f.get('check', '?')):<14}{END} "
              f"{detail(r):<45} {colour}{f.get('reason', '')[:110]}{END}")
    verdict = r.get("adom_verdict")
    if verdict is None:
        if not findings:
            print(f"{GREY}{t}  observed        {r.get('event')}  {detail(r)}{END}")
        return
    if verdict == "block":
        tag = f"{RED}{BOLD}BLOCKED       {END}" if r.get("returned") == "deny" else f"{RED}WOULD BLOCK   {END}"
    else:
        tag = f"{GREEN}allowed       {END}"
    print(f"{t}  {tag} {detail(r):<45} {r.get('latency_ms', '?')}ms  {GREY}{r.get('reason', '')[:90]}{END}")


def _recompute(r):
    r = dict(r)
    h = r.pop("hash", None)
    body = json.dumps(r, sort_keys=True, separators=(",", ":"))
    return h, hashlib.sha256((str(r.get("prev_hash")) + body).encode()).hexdigest()


def chain_report(records):
    """Classify every break in the chain.
      modified - the record's content no longer matches its own hash (it was edited)
      fork     - record is intact but points at an earlier record, not the one before it
                 (two hooks wrote at the same moment; the v0.1-v0.3 race, fixed in v0.3.1)
      gap      - record is intact but points at a hash not in the log (records removed)
    """
    breaks, prev, seen = [], "0" * 64, {"0" * 64}
    for i, r in enumerate(records):
        stored, actual = _recompute(r)
        if stored != actual:
            breaks.append((i, "modified"))
        elif r.get("prev_hash") != prev:
            breaks.append((i, "fork" if r.get("prev_hash") in seen else "gap"))
        prev = stored
        seen.add(stored)
    return breaks


def chain_ok(records):
    return not chain_report(records)


def load():
    if not LOG.exists():
        return []
    return [json.loads(l) for l in LOG.read_text().splitlines() if l.strip()]


def unclassified(records=None):
    """Tools denied as unclassified, with the name-based tier ADOM proposes.

    The proposal is a guess from the tool's name and is never execution authority. Review
    each tool yourself, then add the entries you agree with to ~/.adom/tool_tiers.json."""
    rs = load() if records is None else records
    seen = {}
    for r in rs:
        if r.get("tier") == "unknown" and r.get("proposed_tier"):
            e = seen.setdefault(r.get("tool", "?"), {"count": 0, "proposed": r["proposed_tier"],
                                                     "agents": set()})
            e["count"] += 1
            e["agents"].add(r.get("agent", "?"))
    if not seen:
        print("No unclassified tools in the log.")
        return {}
    print(f"{len(seen)} unclassified tool(s). Proposals are guesses from the name - review each one.\n")
    for tool, e in sorted(seen.items(), key=lambda kv: -kv[1]["count"]):
        print(f"  {tool:48} denied {e['count']:>3}x  proposed {e['proposed']:13} "
              f"({', '.join(sorted(e['agents']))})")
    snippet = {"version": 1, "tools": {t: {"tier": e["proposed"]} for t, e in sorted(seen.items())}}
    print("\nStarting point for ~/.adom/tool_tiers.json (edit before saving; consequential tools")
    print("also need \"approved_outbound\": [hosts], and see README for \"agent_approval\"):\n")
    print(json.dumps(snippet, indent=2))
    return seen


def summary():
    rs = load()
    gated = [r for r in rs if r.get("adom_verdict") is not None]
    blocks = [r for r in gated if r["adom_verdict"] == "block"]
    print(f"{BOLD}ADOM x coding agents{END}  log: {LOG}")
    for line in status_lines()[0]:
        print("  " + line)
    agents = {}
    for r in gated:
        agents[r.get("agent", "cursor")] = agents.get(r.get("agent", "cursor"), 0) + 1
    if agents:
        print("  decisions by agent: " + ", ".join(f"{k} {v}" for k, v in sorted(agents.items())))
    print(f"  decisions: {len(gated)}   would-block/blocked: {len(blocks)}   "
          f"actually denied: {sum(r.get('returned') == 'deny' for r in gated)}")
    lat = sorted(r["latency_ms"] for r in gated if isinstance(r.get("latency_ms"), (int, float)))
    if lat:
        print(f"  latency ms  median {lat[len(lat)//2]}   max {lat[-1]}")
    shells = [r for r in gated if r.get("event") == "beforeShellExecution" and r.get("core_verdict")]
    if shells:
        core_b = sum(r["core_verdict"] == "block" for r in shells)
        new_b = sum(r["adom_verdict"] == "block" for r in shells)
        print(f"  shell commands: {len(shells)}   ADOM core policy would block {core_b}   "
              f"Cursor shell policy blocks {new_b}")
    counts = {}
    for r in rs:
        for f in r.get("findings") or []:
            key = LABEL.get(f.get("check"), f.get("check"))
            counts[key] = counts.get(key, 0) + 1
    if counts:
        print("  coding-agent checks: " + ", ".join(f"{k} x{v}" for k, v in sorted(counts.items())))
    reasons = {}
    for r in blocks:
        reasons[r.get("reason", "")] = reasons.get(r.get("reason", ""), 0) + 1
    for reason, n in sorted(reasons.items(), key=lambda x: -x[1])[:10]:
        print(f"  {n:>4} x  {reason[:100]}")
    breaks = chain_report(rs)
    if not breaks:
        print(f"  hash chain: {GREEN}VALID{END}  ({len(rs)} records)")
    else:
        kinds = {}
        for _, k in breaks:
            kinds[k] = kinds.get(k, 0) + 1
        colour = RED if ("modified" in kinds or "gap" in kinds) else YELLOW
        print(f"  hash chain: {colour}BROKEN{END}  ({len(rs)} records)  "
              + ", ".join(f"{k} x{v}" for k, v in sorted(kinds.items())))
        if set(kinds) == {"fork"}:
            print(f"  {YELLOW}all breaks are forks from simultaneous hook writes (logging race in "
                  f"v0.1-v0.3, fixed in v0.3.1); no record was altered or removed{END}")
        else:
            print(f"  {RED}{BOLD}records were altered or removed - investigate{END}")
        print(f"  start a clean log (old one is kept): watch.py --rotate")


def trust():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    active = [(l, k, fn, p) for l, k, fn, p in AGENTS if p.exists()]
    if not active:
        print(f"{RED}No agent config found (~/.cursor/hooks.json, ~/.claude/settings.json){END}")
        return 1
    broken = False
    for label, key, fn, path in active:
        print(f"{BOLD}--- {label}: {path}{END}")
        print(path.read_text())
        h = getattr(health, fn)()
        for line in health_lines(h):
            print(line)
        broken = broken or h["status"] == "broken"
    if broken:
        print(f"{RED}{BOLD}Not trusted: fix the broken items above first.{END}")
        return 1
    d = health.trust_all()
    for k, v in d.items():
        print(f"{GREEN}Trusted {k}: {v[:16]}...{END}")
    print(f"{GREEN}Baseline saved to {BASELINE}{END}")
    return 0


def follow():
    print(f"{BOLD}Watching ADOM decisions on coding agents{END} (Ctrl+C to stop)  "
          f"CU = Cursor, CC = Claude Code\n{GREY}{LOG}{END}")
    lines, state = status_lines()
    for line in lines:
        print(line)
    print()
    while not LOG.exists():
        time.sleep(0.5)
    for r in load()[-15:]:
        show(r)
    last_check = time.time()
    with open(LOG) as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                try:
                    show(json.loads(line))
                except ValueError:
                    pass
                continue
            if time.time() - last_check > 2:             # agent configs watched out-of-band
                lines, new = status_lines()
                if new != state:
                    for line in lines:
                        print(line)
                    state = new
                last_check = time.time()
            time.sleep(0.3)


if __name__ == "__main__":
    import signal
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)   # quiet exit when piped to head/less
    sys.stdout.reconfigure(line_buffering=True)
    try:
        if "--trust" in sys.argv:
            sys.exit(trust())
        if "--rotate" in sys.argv:
            if LOG.exists():
                kept = LOG.with_name(f"decisions-{time.strftime('%Y%m%d-%H%M%S')}.jsonl")
                LOG.rename(kept)
                print(f"Old log kept unchanged at {kept}\nNew log starts on the next agent action.")
            sys.exit(0)
        if "--unclassified" in sys.argv:
            unclassified()
            sys.exit(0)
        summary() if "--summary" in sys.argv else follow()
    except KeyboardInterrupt:
        print()
