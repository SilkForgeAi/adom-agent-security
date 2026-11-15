# Changelog

## Guardrail integrations, OSS reproductions & November 14 evidence — 2026-11-14

- Added [`adom/integrations/`](adom/integrations/) (`tool_guard.py` + `test_tool_guard.py`) including recursive `guard_openai_agent` swarm enforcement, `guard_callable`, `guarded_function_tool`, `guard_langchain_tool`, `guard_llamaindex_tool`, and fail-closed `guard_mcp_handler`.
- Added key-free microbenchmark [`benchmarks/latency_and_encoding/run.py`](benchmarks/latency_and_encoding/run.py) measuring `p50`/`p95`/`p99` sub-millisecond screening latency (`1,000` iterations), `9/9` obfuscated exfil blocks, and `5/5` benign allows.
- Added 4 standalone comparative OSS bypass & defense reproductions in [`reproductions/`](reproductions/) (`openai-agents-python`, `NVIDIA-NeMo/Guardrails`, `snyk/agent-scan`, `superagent-ai/superagent`; `21/21` verified side-by-side tests).
- Published sanitized November 14 frontier scenario & provider conformance evidence with SHA-256 manifests under [`evidence/2026-11-14/`](evidence/2026-11-14/) and historical notes under `benchmarks/*/historical-results/2026-11-14.md`.

## Documentation and evidence update — 2026-10-08

- Added native AgentDojo aggregate comparisons with clean gates, failures and partial coverage.
- Preserved earlier high-utility candidates as separate configurations.
- Added aggregate local worker-stop and timing evidence with source hashes.
- Distinguished the committed reference implementation from later local lifecycle work.
- Added contribution and technical-review guidance; no enforcement source or license change.

## 0.1.0 — 2026-09-28

- Published the exercised ADOM enforcement core.
- Added deterministic and Docker-topology incident replays.
- Added service-owned effect evidence and SHA-256 manifests.
- Wired blast-radius budgets and a circuit breaker into the mandatory gateway path.
- Added historical cross-provider results and upgraded live harnesses to emit sanitized evidence.
- Added CI, threat-model, claims, architecture, and independent-reproduction documentation.

