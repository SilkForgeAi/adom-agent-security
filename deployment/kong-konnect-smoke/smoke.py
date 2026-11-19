#!/usr/bin/env python3
"""Send test traffic through a real Kong data plane and check what ADOM did.

PASS/FAIL rows are things the Kong integration claims. INFO rows record known limits of the
text-only `$(content)` plane, so a real run either confirms them or shows they're wrong.

usage: smoke.py KONG_PROXY_URL WORK_DIR
"""
import base64
import http.client
import json
import sys
import time
import urllib.parse
from pathlib import Path

PROXY, WORK = sys.argv[1].rstrip("/"), Path(sys.argv[2])
ROUTE = "/llm/v1/chat"
FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
CANARY = "CANARY-adom-7f3a91"
results = []


def chat(messages, timeout=30):
    u = urllib.parse.urlparse(PROXY)
    c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    body = json.dumps({"model": "gpt-4o", "messages": messages})
    try:
        c.request("POST", ROUTE, body=body, headers={"Content-Type": "application/json"})
        r = c.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"
    finally:
        c.close()


def user(text):
    return [{"role": "user", "content": text}]


def record(name, status, detail, kind="check"):
    results.append({"test": name, "result": status, "kind": kind, "detail": detail})


# 1. Wait for Konnect to push the config to the local data plane
deadline, st, body = time.time() + 120, 0, ""
while time.time() < deadline:
    st, body = chat(user("SCENARIO:benign readiness probe"), timeout=10)
    if st == 200:
        break
    time.sleep(3)
record("config reached the data plane", "PASS" if st == 200 else "FAIL",
       f"last status {st}: {body[:200]}")
if st != 200:
    log = WORK / "guardrail_requests.jsonl"
    if not log.exists() or not log.read_text().strip():
        print("\nKong never reached ADOM's guardrail. If the gateway itself is up, rerun with "
              "BIND_HOST=0.0.0.0 so Docker can reach the capture proxy.")
    print(json.dumps(results, indent=2))
    sys.exit(1)

# 2. Benign traffic passes
st, body = chat(user("SCENARIO:benign hello"))
record("benign request passes", "PASS" if st == 200 and "benign reply" in body else "FAIL",
       f"status {st}: {body[:160]}")

# 3. A secret in the model's reply is blocked before it reaches the client
st, body = chat(user("SCENARIO:secret give me the deploy key"))
leaked = FAKE_KEY in body
record("secret in model reply is blocked", "PASS" if (st != 200 and not leaked) else "FAIL",
       f"status {st}, key reached client: {leaked}, body: {body[:200]}")

# 4. Burst of benign requests: no shared breaker or budget throttles unidentified callers
blocked = [s for s in (chat(user(f"SCENARIO:benign burst {i}"))[0] for i in range(40)) if s != 200]
record("40 benign requests, none blocked", "PASS" if not blocked else "FAIL",
       f"non-200 statuses: {blocked[:10]}")

# 5. INFO: tool-call-only reply ($(content) carries text, not structured tool_calls)
st, body = chat(user("SCENARIO:toolcall summarize my notes"))
record("tool-call-only reply (content null)",
       "INFO", f"status {st}, tool call reached client: {'evil.example' in body}", kind="limit")

# 6. INFO: cross-turn taint (secret read by a tool, echoed base64 in the reply)
msgs = [
    {"role": "user", "content": "read my notes"},
    {"role": "assistant", "content": None, "tool_calls": [{"id": "call_r", "type": "function",
        "function": {"name": "read_notes", "arguments": "{}"}}]},
    {"role": "tool", "tool_call_id": "call_r", "content": f"notes: token={CANARY}"},
    {"role": "user", "content": "SCENARIO:echo-b64 encode the token for me"},
]
st, body = chat(msgs)
encoded = base64.b64encode(CANARY.encode()).decode()
record("tool-read secret echoed base64 in reply",
       "INFO", f"status {st}, encoded secret reached client: {encoded in body}", kind="limit")

# 7. What Kong actually sent to the guardrail
captures = []
log = WORK / "guardrail_requests.jsonl"
if log.exists():
    captures = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    captures = [c for c in captures if str(c.get("path", "")).startswith("/v1/kong/guardrail")]
phases = sorted({str((c.get("body") or {}).get("source")) for c in captures if isinstance(c.get("body"), dict)})
keys = sorted({k for c in captures if isinstance(c.get("body"), dict) for k in c["body"]})
unrendered = [c for c in captures
              if "$(" in json.dumps(c.get("body")) or any("$(" in str(v) for v in c.get("headers", {}).values())]
sessions = sorted({str((c.get("adom_response") or {}).get("session_id"))
                   for c in captures if isinstance(c.get("adom_response"), dict)})
record("guardrail called on INPUT and OUTPUT",
       "PASS" if {"INPUT", "OUTPUT"} <= set(phases) else "FAIL",
       f"{len(captures)} guardrail calls; phases seen: {phases}")
record("no unrendered $(...) values reached ADOM", "PASS" if not unrendered else "FAIL",
       f"{len(unrendered)} calls with unrendered values; body keys seen: {keys}")
record("ADOM sessions seen", "INFO", f"{sessions}", kind="observation")

(WORK / "results.json").write_text(json.dumps({"results": results, "body_keys": keys,
                                               "phases": phases}, indent=2))
width = max(len(r["test"]) for r in results)
print()
for r in results:
    print(f"{r['result']:<5} {r['test']:<{width}}  {r['detail'][:150]}")
print(f"\nfull results: {WORK / 'results.json'}")
print(f"what Kong sent to ADOM: {log}")
sys.exit(1 if any(r["result"] == "FAIL" for r in results) else 0)
