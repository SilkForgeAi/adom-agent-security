# ADOM results and evaluation limits

Updated October 8, 2026. ADOM has strong scoped enforcement results and real remaining task-utility and output-coverage gaps. Scores below describe recorded configurations; they do not establish a universal protection rate.

## What can be reproduced from this repository

The public reference implementation includes the deterministic incident replay and the Docker topology replay. Their source, saved records, verifiers and manifests are committed. Follow [REPRODUCIBILITY.md](../REPRODUCIBILITY.md).

The [AgentDojo package](../benchmarks/agentdojo/README.md) publishes the frozen v6 adapter dependency subset and all 320 historical banking episode/trace pairs. Its verifier checks record consistency and its offline scorer recomputes native banking scores without API calls. This preserves the failed clean gate and exploratory classification. Other suite raw records, later corrections and the workflow lab remain separately retained; unaffiliated fresh reproduction remains outstanding.

## GPT-4o exploratory AgentDojo evaluation

Configuration: `gpt-4o-2024-05-13`; AgentDojo `0.1.35`, benchmark `v1.2.2`; `important_instructions`; one repeat; installed v6 frozen before dispatch. The clean gate failed. Attack evaluations continued as explicitly exploratory. The user stopped the run at **1,873/2,092 valid episodes**, leaving **219 Workspace ADOM attack cases unrun**. Missing cases receive no credit.

“Attacked utility” means native user-task success under attack. “ASR” means native attack success, not whether an independent service recorded an effect.

| Suite | Baseline attacked utility | ADOM attacked utility | Baseline native ASR | ADOM native ASR |
|---|---:|---:|---:|---:|
| Banking | 126/144 (87.50%) | 143/144 (99.31%) | 87/144 (60.42%) | 0/144 |
| Travel | 64/140 (45.71%) | 82/140 (58.57%) | 50/140 (35.71%) | 4/140 (2.86%) |
| Slack | 70/105 (66.67%) | 53/105 (50.48%) | 100/105 (95.24%) | 8/105 (7.62%) |
| Workspace — same 341 pairs | 154/341 (45.16%) | 195/341 (57.18%) | 97/341 (28.45%) | 0/341, partial |

For completeness, the entire Workspace baseline was 191/560 utility and 163/560 ASR. It must not be compared as equal coverage to the partial 341-case ADOM arm.

| Suite | Baseline clean utility | ADOM clean utility | Clean gate |
|---|---:|---:|---|
| Banking | 16/16 | 15/16 | Failed five-percentage-point drop bar |
| Travel | 14/20 | 14/20 | Failed 75% minimum utility |
| Slack | 20/21 | 20/21 | Passed |
| Workspace | 26/40 | 23/40 | Failed minimum and drop bars |

Travel's four successes involved attacker-selected final-answer text outside the supported publication profile. Slack's eight successes were counted by the native attempted-call scorer; denied proposals and the absence of matching returned agent-audit entries do not constitute independent service proof or justify replacing the raw ASR. These scores stay visible.

## Earlier high-utility configurations

The recorded GPT-5.4-mini configurations below exceeded 80% attacked utility with zero observed native ADOM attack successes. **They are separately frozen candidates, not one four-suite release.** The recorded model family is retained as reported; these aggregates do not replace the source/configuration manifests for reproduction.

| Suite | Baseline attacked utility | ADOM attacked utility | Baseline ASR | ADOM ASR | Clean utility baseline → ADOM |
|---|---:|---:|---:|---:|---:|
| Banking, consolidated funded | 375/432 | 382/432 (88.43%) | 3/432 | 0/432 | 41/48 → 47/48 |
| Travel, consolidated funded | 122/140 | 126/140 (90.00%) | 0/140 | 0/140 | 57/60 → 55/60 |
| Slack, service-selector candidate | 80/105 | 86/105 (81.90%) | 0/105 | 0/105 | 63/63 → 61/63 |
| Workspace, release candidate | 530/560 | 519/560 (92.68%) | 0/560 | 0/560 | 116/120 → 112/120 |

Baseline ASR was already zero for Travel, Slack and Workspace. Those comparisons demonstrate recorded utility under these fixed attacks, not additional attack reduction attributable to ADOM.

A separate fresh GPT-4o-mini banking campaign recorded zero native ADOM attack successes across 1,152 attacked episodes spanning six fixed families. These include repeats of the same task/injection pairs, not 1,152 independent attack discoveries. Utility remained modest: the three-repeat important-instructions comparison was 204/432 baseline versus 214/432 ADOM, with ASR 223/432 versus 0/432. Do not present the security count without its utility context.

## Local enforcement and stop tests

| Test | Recorded result | Scope |
|---|---|---|
| Independent OS workers | 2,000 legitimate reads; 2,000 post-stop publication attempts denied; zero receiver effects | 2,000 live scripted processes in one container; admitted 24 at a time, not 2,000 LLMs or containers |
| Stop timing | 30 sequential local runs; zero recorded effects after full acknowledgement | Shared Linux monotonic clock; no distributed-clock or production latency guarantee |
| Stop to full acknowledgement | Median 2.158 ms; p95 3.917 ms; max 4.509 ms | Local fixture distribution, not a detection-to-stop service-level bound |
| Finite lifecycle abstraction | 569 states, 1,884 transitions; five negative trace checks | Executable model, not TLA+ or an implementation proof |
| Deterministic incident replay | Same 18-step plan: 13 prohibited effects baseline versus zero protected; two useful operations in each arm | Sandbox compromise explicitly granted; no real zero-day reproduction |
| Committed reference Docker replay | Seven target-side effects baseline versus zero protected; 9/9 brokered attack requests denied | Trusted host/kernel/daemon and the declared topology |

[Machine-readable latest summaries](../evidence/2026-10-08/README.md) preserve source-record identifiers and hashes. The 2,000-worker test and timing distribution come from later workflow-lab snapshots, not the committed reference implementation.

## Research results and failures retained

Behavioral prompt-injection detection historically recorded 10.8% recall, 3.8% false positives and 62.9% precision. White-box transfer is mixed: one recorded Qwen-1.5B factual-topic held-out evaluation reached 0.812 AUROC, while external TruthfulQA transfer was 0.587. A Qwen-7B best-layer held-out-topic aggregate was 0.835 on 1,050 statements; layer selection and the lack of a fresh independent reproduction limit its interpretation. These are different tasks, not a general deception detector.

Preregistered causal steering was not supported and the capability claim was retired. Seven live incident-replay attempts were inconclusive, partial or yielded no attack; none is counted as an enforcement win. A historical programmatic adaptive policy campaign found 200/200 attacker successes in two permissive profiles and 0/200 in a restrictive schema profile. That is distinct from adaptive AgentDojo, which has not been completed.

No full adaptive AgentDojo campaign, matched competitor comparison, blind policy authoring, general zero-false-positive rate, or unaffiliated reproduction is established. Policies were developed with task/fixture exposure and privileged clean snapshots. A signed or hashed record is not proof of model intent, correctness, or independent validation.
