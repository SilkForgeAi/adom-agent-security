# Architecture

ADOM treats an autonomous agent as a potentially compromised workload. The protected asset is not
the model's chain of thought; it is the authority to create effects.

## Trust domains

1. **Agent domain:** model context, transcript, generated code, workspace, and tool arguments.
2. **Enforcement domain:** gateway, budgets, policy versions, credential issuance, and executor.
3. **Service domain:** protected targets and effect records that the agent cannot rewrite.
4. **Verification domain:** topology capture, receipts, manifests, and independent state checks.

## Mandatory path

Every consequential action passes through `MediatedAgentGateway`:

1. Freeze arguments once to prevent time-of-check/time-of-use mutation.
2. Consume the agent's action or consequence budget.
3. Apply strict deny-unknown action policy.
4. Independently screen outbound destination and data flow.
5. Optionally check the tool's attested capability envelope.
6. Execute only after every applicable plane permits the action.
7. Inspect returned data before it reaches model context.
8. Record success or failure and trip the circuit when thresholds are reached.

The gateway cannot make itself mandatory from Python alone. Production deployment must remove
alternate network and credential paths using namespaces, workload identity, egress routing, and a
separate enforcement service.

## Why the circuit breaker matters

A safe denial can still become a cost or availability attack if a compromised agent retries it
thousands of times. `BlastRadiusController` bounds actions, destructive effects, spend, outbound
bytes, and failures. An open circuit suppresses work before executor dispatch and can isolate
dependent agents.

## Evidence

Policy decisions are not treated as proof of prevention. The replay verifier reads service-owned
effect logs and Docker network membership, then checks that protected effects did not occur.

