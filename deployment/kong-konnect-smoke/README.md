# ADOM + Kong AI Gateway smoke test (real Kong, via Konnect)

Runs ADOM's generated Kong config on a real Kong Gateway Enterprise data plane, licensed
through a Konnect account (the free trial works), and sends test traffic through it.

```bash
./deployment/kong-konnect-smoke/run.sh
```

Needs Docker Desktop running, Python 3.10+, and a Konnect personal access token saved in
`~/.adom/konnect-token` (`chmod 600`). Non-US Konnect accounts: `KONNECT_REGION=eu` (or au, me, in).

The script creates a Konnect control plane named `adom-smoke` and a local gateway with Kong's
official quickstart, loads the config from `adom kong-guard --emit-deck` with decK, runs the
checks in `smoke.py`, then deletes the containers and the `adom-smoke` control plane
(`KEEP_KONG=1` keeps them). Kong's quickstart deletes and recreates a control plane of that
name, so don't use `adom-smoke` for anything else.

A capture proxy between Kong and ADOM records exactly what Kong sends to the guardrail, so the
run shows which `$(...)` variables Kong really renders. Results and logs go to
`~/.adom/kong-smoke/` (`results.json`, `guardrail_requests.jsonl`, `deck.log`, `quickstart.log`).

| Row | Meaning |
|---|---|
| PASS / FAIL | A claim the Kong integration makes: benign traffic passes, a raw secret-shaped string in the model reply is blocked, no shared breaker throttles callers, the guardrail is called on INPUT and OUTPUT, no unrendered variables reach ADOM |
| INFO | A known limit of the text-only `$(content)` plane, recorded so a real run confirms it: tool-call-only replies and cross-turn taint are not visible to the guardrail |
