# Changelog

## Fail-closed integration fixes, reproducible repros & packaging — 2026-11-19

- **Model API proxy:** streaming responses are blocked (HTTP 502) until the stream inspector ships, and inspection errors on non-streaming responses block instead of forwarding uninspected bytes.
- **Coding-agent hooks:** unrecognized payloads fail closed in enforce mode; known non-gated Claude Code events (PostToolUse after non-write tools, Stop, SessionStart, ...) get "no opinion" so finished actions are not reported as blocked.
- **Kong AI Gateway, verified on real Kong:** Kong Gateway Enterprise 3.16 via Konnect accepted the config and blocked a raw secret-shaped string in the model reply (`evidence/2026-11-19/`, harness `deployment/kong-konnect-smoke/`). The run caught `metrics.block_details` (Kong's field is `block_detail`); fixed, with tests pinning the plugin config to Kong's schema. The config now sets `stop_on_error: true` and `ssl_verify: true`. Confirmed limits: tool-call-only replies get no OUTPUT guardrail call; tool output arrives unlabeled in `$(content)`, so encoded secrets read by tools are not caught on this plane. `docs/KONG_AI_GATEWAY_ARCHITECTURE.md` rewritten to state exactly what the LLM and MCP planes do, with Kong source and doc references; corrected claims that `adom mcp-http` writes an audit log and that the Kong plane catches encoded secrets.
- **Kong AI Gateway:** `kong-guard` always denies unknown tools; the engine screens `$(content)` text and any structured body together and ignores unrendered `$(...)` values; unidentified sessions get per-request screening without a shared gateway-wide breaker or budget (`--session-scope`, `--anonymous-blast-radius`); the decK config uses only Kong-documented template variables.
- **`adom mcp-http`:** TLS with SNI to pinned upstream IPs; MCP streamable HTTP (session id returned to the client, 202 notification replies, SSE replies parsed and screened, GET 405, DELETE forwarded); taint learned from `resources/read` and `prompts/get`; fallback across validated addresses for dual-stack upstreams.
- **Packaging:** `adom bench` works from a normal `pip install` (benchmark moved to `adom/bench.py`; `benchmarks/latency_and_encoding/run.py` remains as a wrapper). CI checks the installed CLI outside the source tree and runs the `adom/api` tests.
- **Reproductions:** `reproductions/run_reproduction.sh` fetches each pinned upstream commit into its own virtualenv and runs the side-by-side tests; machine-specific default paths removed. All four (21/21 tests) re-verified from a clean checkout.
- **Accuracy pass across docs:** benchmark headlines now carry their caveats (author-run and not re-runnable from this repo; the AgentDyn numbers are not a held-out test because generic code was revised after the November 16 run on the same suites; the Router result is one authored workflow); write-ups about other projects separate documented or deliberate upstream behavior from gaps and drop "bypass" wording; hook defaults, `ENGINEERING_STATUS.md`, `SECURITY_CLAIMS.md` and the Inspect integration notes (checked against `inspect-ai 0.3.291` source) match the code; references to modules not in this repository were removed. The LiteLLM and OpenHands rows were re-checked against their pinned upstream source and current upstream `main`. `NOTICE` now lists third-party licenses (Kong Apache-2.0 for the `guard-prompt.lua` test reference; OpenAI Agents SDK, NeMo Guardrails, Snyk `agent-scan`, Superagent for the reproductions).

## Adaptive AutoDojo & Unseen AgentDyn Evaluation Summary — 2026-11-16

- Added hash-pinned adaptive attack and unseen-suite generalization summary under [`evidence/2026-11-16/`](evidence/2026-11-16/README.md) with CI manifest verification:
  - **AutoDojo adaptive black-box attack (`banking`, `144` pairs, `gpt-4o-2024-11-20` optimizer vs. `gpt-4o-mini-2024-07-18`):** `0/144` (`0.00%`) ASR under both live ADOM-targeted optimization (`56.94%` vs `46.53%` utility) and AutoDojo's shipped `no_defense` adaptive cache (`84/144 = 58.33%` baseline ASR → `0/144`, `59.72%` vs `41.67%` utility).
  - **Unseen AgentDyn suites (`shopping`, `github`, `dailylife`, zero per-suite rules):** query-time `adom_query` cut `shopping` `important_instructions` ASR from `43/180 (23.89%)` to `6/180 (3.33%)` while doubling clean utility (`3/20 → 7/20`), and documented multi-step unseen clean-utility drops (`1/20` on `github`/`dailylife`; `0/60` on zero-LLM `adom_generic`) explicitly as an open research frontier.

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

