# Security claims and limitations

Updated November 19, 2026. Cite only the supported claims, with their scope.

## Supported claims (reproducible from this repository)

- **Incident replay.** The deterministic replay runs the same 18-step plan with and without ADOM;
  in the protected run legitimate work completes and prohibited effects are zero. In the Docker
  replay the protected target records zero effects, all nine brokered attack requests are denied,
  one circuit trip occurs and six later requests are suppressed. The verifier reads service-owned
  effect records and saved network membership, not a policy-authored label.
- **Provider independence.** The enforcement core decides the same way regardless of which model
  produced an action, when that action is mediated through it.
- **Upstream gap reproductions.** Four behaviors in pinned commits of the OpenAI Agents SDK, NeMo
  Guardrails, Snyk `agent-scan` and Superagent reproduce with `reproductions/run_reproduction.sh`,
  with ADOM's behavior on the same input. Several are documented upstream design choices; see each
  write-up.
- **Kong AI Gateway (real Kong).** On Kong Gateway Enterprise 3.16 via Konnect, ADOM's generated
  config loads, the guardrail runs on requests and replies, and a raw secret-shaped string in a
  model reply is blocked before reaching the client. Re-run with
  `deployment/kong-konnect-smoke/run.sh`.
- **Fail-closed integration behavior.** The model API proxy blocks uninspected responses
  (including all streaming responses); the MCP gateways and the Kong and Inspect integrations
  answer "block" on internal errors; coding-agent hooks block unrecognized payloads in enforce
  mode. Each has tests.

## Recorded but not reproducible from this repository

AgentDojo, AutoDojo, AgentDyn, the workflow lab and the worker-stop test are hash-pinned
author-run summaries. Their adapters and logs are not here. Policies were developed with
exposure to the benchmark tasks, retry hints return correct targets from a clean snapshot, and
the Nov 17 AgentDyn numbers followed code changes made after running those suites. See
[results](RESULTS.md).

## Unsupported claims

- ADOM does not reproduce, discover, patch or prevent the Artifactory zero-day.
- The injected sandbox-loss condition is not evidence that ADOM survives every real escape.
- A Docker topology on one daemon is not proof against a kernel, hypervisor or daemon compromise.
- Historical frontier-model reports are not equivalent to the sealed container evidence.
- A finite scenario set cannot establish universal containment.
- On Kong's LLM plane ADOM does not see tool calls in replies, does not catch encoded secrets as
  shipped, and does not screen requests. The MCP plane has not run behind real Kong.
- Streaming model responses are refused by the model API proxy, not inspected.
- No result has been reproduced by an unaffiliated party; no external audit; no production
  deployment; no matched comparison with another defense.

## Correct public wording

> ADOM contained every prohibited effect in a reproducible synthetic incident replay after a
> declared sandbox compromise, while preserving the tested legitimate operation.

> On a real Kong AI Gateway, ADOM blocked a secret in a model's reply before it reached the
> client. Kong's guardrail hook sends only message text, so tool calls are enforced at ADOM's
> MCP and tool layer instead.

Avoid wording such as "ADOM stops zero-days", "unhackable", "guaranteed containment", "unseen
benchmark" for the Nov 17 AgentDyn runs, or "bypass" for documented upstream behavior.
