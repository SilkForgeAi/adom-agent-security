# Engineering status and supported boundary

Updated October 8, 2026. The repository is a runnable reference implementation plus an evidence index. Later local engineering is documented separately so readers can distinguish available source from recorded development.

| Area | Committed public reference | Later local work recorded, source not included here |
|---|---|---|
| Action authorization | Gateway, strict unknown-tool policy, capability envelope, consequence budgets and circuit breaker | Exact-action/identity binding, persistent delegation and authority budgets |
| Delivery lifecycle | Synchronous replay/executor path | Authorization before dispatch, durable execution/outbox state, idempotency, explicit UNKNOWN and service-receipt reconciliation |
| Revocation | Reference budgets/circuit behavior | Service-side authority epoch fences, full-stop acknowledgement, stale queued-request rejection |
| Deployment | Deterministic replay and Docker network topology | Restricted workflow-lab profile, continuous checks, persistence and recovery cases |
| Monitoring | Reference returned-output observation and historical harnesses | Signals may escalate, suspend or require approval, but cannot grant authority |
| Evidence | Committed service-owned records, saved topology, verifier and manifests | Native AgentDojo score audits, receiver receipts, forced post-revocation attempts and timing distributions |

## Later execution lifecycle

The later local workflow separates authorization, dispatch and actual effects:

1. Bind the request ID to its identity, exact action and authority epoch.
2. Persist authorization and delivery intent before dispatch.
3. Have the executor check the current authority fence before committing the supported effect.
4. Reconcile the executor's receipt against the broker record. A timeout alone leaves an unknown outcome; a retry must not duplicate the effect.
5. On revocation, stop admission and require every supported receiver to acknowledge its fence before reporting fully stopped.
6. On restart, preserve budgets and revocation and reject stale queued requests or approvals.

This protocol relies on cooperating executors and an intact enforcement boundary. It does not constrain effects that bypass the declared path or already-committed irreversible work.

## Monitoring and failure rules

Monitoring only tightens restrictions. Degraded monitoring can require approval for consequential actions, still subject to deterministic authorization, budgets and revocation. Degraded enforcement fails closed; human approval cannot replace an unavailable or compromised enforcement boundary. Unknown action classes default to denial in the supported enforcement profile.

The older reference code and platform-specific hooks must be evaluated on their own behavior; these later design properties are not automatically inherited by every integration.

## Trust and deployment limits

The agent must not possess direct service credentials, administrative sockets, broker state access or an alternative route to the protected service. The supported local deployments trust the host, kernel, Docker daemon and enforcement components. Assuming an agent's sandbox is compromised is not evidence of surviving a kernel or hypervisor exploit. The public reference is a development/research artifact, not a certified production product.

## Next reviewable engineering work

Publish a carefully scoped, licensed subset of the later lifecycle implementation with its own pinned build and tests; reproduce it outside the author's machine; evaluate a narrow external integration; improve utility and final-output coverage; and connect implementation traces to an explicit model. No implementation proof or completed outside reproduction is claimed.

## AgentDojo reproducibility release

The [public evaluation package](../benchmarks/agentdojo/README.md) now includes the exact required v6 adapter source, dependency lock, 320 historical banking episodes and traces, standard-library verifier, offline native scorer and separate paid banking validation runner. Historical native scores recompute locally; the failed clean gate and exploratory classification remain unchanged. The old global dispatch log also includes checker/reference calls and is not independent effect evidence; the scorer uses executor audit/native tool results, and the new logger captures only agent-query dispatches. This release does not include later private corrections or establish unaffiliated reproduction.
