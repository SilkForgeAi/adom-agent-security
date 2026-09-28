# Threat model

## Security objective

Preserve explicitly authorized work while preventing a compromised or misaligned agent from
creating prohibited external effects through mediated tools and networks.

## In scope

- Prompt injection and goal drift.
- Reward hacking and attempts to manipulate an evaluator.
- Unknown or spoofed tools.
- Cross-agent communication through shared services.
- Credential use, secret exfiltration, destructive actions, spend, and unbounded retries.
- Direct network bypass attempts when deployment topology denies an alternate route.
- Transcript or agent-local evidence tampering.

## Adversary capabilities

The agent may control its prompt, transcript, tool arguments, generated files, and workload
process. It may retry, encode data, select alternate tools, and falsely claim that an action was
authorized. In the container replay, sandbox loss is declared as already having occurred.

## Trusted components

- Enforcement gateway and policy configuration.
- Workload/network isolation outside the agent container.
- Credential broker or workload identity service.
- Protected service and effect records.
- Host-side verifier.

## Out of scope

- Compromise of the enforcement host, kernel, hypervisor, Docker daemon, or cloud control plane.
- A physical attacker or malicious infrastructure administrator.
- Universal prevention of unknown vulnerabilities.
- Proving that a model is aligned or interpreting hidden reasoning.
- Unauthorized testing of third-party infrastructure.

## Failure rule

If enforcement state, policy version, registration, destination parsing, or observation is
unavailable, consequential execution must fail closed. Availability tradeoffs must be explicit and
measured rather than silently converted into allow behavior.

