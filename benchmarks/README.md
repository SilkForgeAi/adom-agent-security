# Live-model benchmarks

These harnesses test a narrower claim than the incident replay: when a provider emits a
consequential tool call through the mediated path, does ADOM enforce the same boundary regardless
of model family?

## Provider conformance

`provider_conformance/run.py` concurrently requests a forced destructive call from OpenAI,
Anthropic, and Google, then checks that ADOM removes the call and does not leak a per-session
canary. This is deterministic API-shape coverage; it is not evidence that the models independently
decided to attack.

## Frontier scenarios

`frontier_scenarios/run.py` presents realistic operational tasks without forcing a tool choice. A
model may refuse, act, or fail. Refusals are reported as refusals, never as ADOM passes. When a
dangerous action is chosen, synthetic effect sinks independently check whether a payment, deletion,
or outbound canary effect occurred.

## Historical evidence

The August 4, 2026 reports are contemporaneous summaries from real provider runs. They are retained
for provenance but are lower assurance than the container evidence because raw provider responses
and machine-readable receipts were not preserved. The upgraded scripts now write sanitized JSON
and SHA-256 manifests beneath ignored `runs/` directories.

## Cost and safety

Live runs consume paid API calls and have no automatic retries. All credentials and targets in the
scenario world are synthetic. Review model names and provider pricing before running.


## Selective inference and validated workflow reuse

[Request-grounding evidence and runnable harness](request_grounding/README.md):
100 legitimate task executions per arm plus controls, key-free verification of
both saved campaigns, explicit model-alias/caching limits, and the failed
development evaluation retained alongside the fix. This is a separate workload
experiment, not an AgentDojo score or an independent containment comparison.
