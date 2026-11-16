# Changelog

## Hash-pinned 4-suite AgentDojo & cost-reduction summary — 2026-11-15

- Added hash-pinned AgentDojo `v1.2.2` summary (`gpt-4o-mini-2024-07-18`, `important_instructions`, `949` task×injection pairs per condition) and `latency_and_encoding_summary.json` under [`evidence/2026-11-15/`](evidence/2026-11-15/README.md) with SHA-256 manifest checks in CI:
  - Clean gates passed `4/4` (`70/97 → 74/97`, with `authorized_action_shapes` clean-snapshot target recovery on denied retries); raw native ASR `268/949 (28.24%) → 7/949 (0.74%)` (`0/929` non-preference executed attacker side effects across eligible pairs); utility under attack `397/949 (41.83%) → 603/949 (63.54%)`.
- Updated `README.md` and `docs/RESULTS.md` to align all latency figures with `latency_and_encoding_summary.json` (`0.0393–0.1008 ms` `p50`, `0.1177–0.2937 ms` `p99`), define AgentDojo's 4-attack Paper-Max metric, and highlight the `-66.98%` API cost reduction (`benchmarks/request_grounding`).

## Strongest enforcement modules, MCP proxies, coding-agent hooks & CLI — 2026-11-15

- Added `adom/enforcement/` modules (`action_tiers`, `approvals`, `audit_chain`, `review`, `supply_chain`, `tool_contracts`), `adom/integrations/mcp_gateway.py` (stdio MCP gateway), and `adom/integrations/mcp_http_proxy.py` (IP-pinned SSRF-hardened remote MCP HTTP proxy).
- Added multi-client offline fail-closed coding-agent hooks under `cursor_hook/` (`adom_agent_hook.py` for Cursor, Claude Code, Codex, and GitHub Copilot) plus specs under `spec/`.
- Added unified `adom` CLI (`adom/cli.py`, `[project.scripts]` in `pyproject.toml`: `hook`, `mcp-stdio`, `mcp-http`, `verify-chain`, `bench`) and expanded CI (`verify.yml`) to run all `138` unit/integration tests alongside `68` selective-inference tests.

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

