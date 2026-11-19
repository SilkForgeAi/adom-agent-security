# Engineering status and supported boundary

Updated November 19, 2026. This page separates what is in this repository and tested, what was
recorded from work that is not in this repository, and what has not been done.

## In this repository, with tests

| Area | What exists | Tested how | Known limits |
|---|---|---|---|
| Enforcement core | `MediatedAgentGateway` (single action entry point), strict deny-unknown policy (`ModelProxyPolicy`), frozen-argument screening (`action_kernel`), egress policy and HTTP(S) egress proxy (host allowlist, header and body secret scan, DNS pinning), blast-radius budgets and circuit breaker, tool contracts, exact-action approvals, action tiers | Unit and integration tests in CI; deterministic and Docker incident replays | Mediation holds only if the deployment routes every action through it; budgets are per process |
| Audit | SHA-256 hash-chained JSONL with optional HMAC key and external head anchor; `adom verify-chain` | Tests; CI verifies committed chains | Unkeyed by default; a chain without an external anchor cannot show a truncated tail |
| Model API proxy (`adom/api/model_proxy.py`) | Inspects non-streaming OpenAI Chat, Anthropic Messages and Gemini responses; blocks on inspection errors; **blocks streaming responses** | Unit tests with a fake upstream | Not run against live provider APIs; the streaming inspector is not included, so streaming is refused rather than inspected |
| MCP stdio gateway (`adom mcp-stdio`) | Deny-unknown tools, argument screening, `resources/read` / `prompts/get` screening, cross-tool taint, blocks server-initiated sampling/elicitation, audit chain | Tests | stdio transport only |
| MCP HTTP proxy (`adom mcp-http`) | Streamable HTTP (JSON and SSE replies, sessions, 202 acks), DNS-pinned upstream with TLS verification, same screening and taint as stdio | Tests against a fake server shaped like the official SDK server | No audit log; refuses servers that send requests to the client mid-call |
| Kong AI Gateway | `adom kong-guard` for `ai-custom-guardrail`; decK config generator | Tests, plus a real run on Kong Gateway Enterprise 3.16 via Konnect ([`evidence/2026-11-19/`](../evidence/2026-11-19/README.md)) | As shipped, blocks raw secret-shaped strings in model replies only; see [Kong scope](KONG_AI_GATEWAY_ARCHITECTURE.md). MCP plane not yet run behind Kong |
| UK AISI Inspect | `adom_approver` for `inspect_ai` approval policies | Tests | See [Inspect integration](UK_AISI_INSPECT_INTEGRATION.md) |
| Framework tool guards | Plain functions, OpenAI Agents SDK function tools (across handoffs), LangChain, LlamaIndex, MCP handlers | Tests; OpenAI SDK behavior checked against the pinned SDK in `reproductions/` | Hosted/built-in OpenAI tools are not covered |
| Coding-agent hooks | Cursor, Claude Code, Codex, GitHub Copilot | Tests | Default mode is observe (logs, never blocks); `ADOM_MODE=enforce` blocks and fails closed. Claude Code hooks fail open if the script cannot start (platform behavior) |
| Reproductions | Four upstream guardrail-gap reproductions, runnable with `reproductions/run_reproduction.sh` | Re-run from a clean checkout on 2026-11-19 (21/21) | Two more (LiteLLM, OpenHands) live in separate repositories |

## Recorded, but the source is not in this repository

These results are published as hash-pinned summaries. The hashes prove the summary files have not
changed since they were committed; they do not let anyone re-run the experiments.

- AgentDojo, AutoDojo and AgentDyn adapters and per-episode logs (see [results](RESULTS.md) for
  configurations and caveats).
- The workflow lab: authorization before dispatch, durable delivery, idempotency, explicit unknown
  outcomes, service-side revocation fences, the 2,000-worker stop test and timing distribution.
- The streaming response inspector, the mediation-path attestor and a container-hardening /
  seccomp module referenced by earlier designs.

### The later execution lifecycle (as designed in the local work)

1. Bind the request ID to its identity, exact action and authority epoch.
2. Persist authorization and delivery intent before dispatch.
3. Have the executor check the current authority fence before committing the supported effect.
4. Reconcile the executor's receipt against the broker record. A timeout alone leaves an unknown
   outcome; a retry must not duplicate the effect.
5. On revocation, stop admission and require every supported receiver to acknowledge its fence
   before reporting fully stopped.
6. On restart, preserve budgets and revocation and reject stale queued requests or approvals.

This protocol relies on cooperating executors and an intact enforcement boundary.

## Not done

- No reproduction of any result by someone unaffiliated with the project.
- No external security audit and no production deployment.
- No matched, same-setup comparison against another defense.
- No implementation proof; the lifecycle model is an executable abstraction, not TLA+.
- Budgets and breakers are in-memory per process; a fleet needs a shared store.

## Trust and deployment limits

The agent must not hold direct service credentials, administrative sockets, broker state or an
alternative route to the protected service. The supported local deployments trust the host,
kernel, Docker daemon and enforcement components. Assuming an agent's sandbox is compromised is
not evidence of surviving a kernel or hypervisor exploit. This is a development and research
artifact, not a certified production product.
