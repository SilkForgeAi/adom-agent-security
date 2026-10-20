# ADOM same-workload live repeat: 100 legitimate tasks per arm

The complete 240-execution campaign finished. All five original aggregate criteria passed. This is five repetitions of the same authored workload, with fresh identities and real outputs; it is not 100 unique semantic tasks or independent validation.

| Measure | Always model + shared enforcement | ADOM routing + live fallback |
|---|---:|---:|
| Legitimate task completion | 100/100 | 100/100 |
| Exact tasks | 60/60 | 60/60 |
| Source interpretation tasks | 40/40 | 40/40 |
| Controls | 10/20 | 20/20 |
| All outcomes correct | 110/120 | 120/120 |
| API calls | 120 | 40 |
| Legitimate API cost | $1.582210 | $0.522500 |
| Cost per successful legitimate task | $0.015822 | $0.005225 |
| All-case API cost | $1.931485 | $0.522500 |
| Median legitimate-task latency | 1426.18 ms | 32.49 ms |
| p95 legitimate-task latency | 2064.65 ms | 1845.45 ms |
| Authority violations | 0 | 0 |
| Unexpected control effects | 0 | 0 |

Legitimate cost per success fell 66.98%; median latency fell 97.72%; aggregate p95 improved 10.62%. The 50% cost and median-latency thresholds, no-lower legitimate success, zero authority violations, and no-worse aggregate p95 all passed. No failures were removed or retried.

## Repetition variability

| Repetition | Baseline / ADOM task success | Baseline / ADOM p95 ms | Cost savings |
|---|---|---|---:|
| 1 | 20/20 / 20/20 | 2199.52 / 1509.20 | 71.02% |
| 2 | 20/20 / 20/20 | 2066.74 / 1548.41 | 59.79% |
| 3 | 20/20 / 20/20 | 1725.40 / 1968.26 | 63.41% |
| 4 | 20/20 / 20/20 | 2009.78 / 1514.77 | 67.88% |
| 5 | 20/20 / 20/20 | 1579.35 / 1850.99 | 72.30% |

ADOM p95 was worse in repetitions 3 and 5 despite the aggregate improvement. These small-sample tails reflect network/model latency and must not be presented as uniformly improved. All five repetitions achieved equal legitimate task success and more than 50% observed cost savings. Repetitions were interleaved within one randomized campaign with shared warm registries and server prompt caching; they are not independent cold-start runs.

## Execution and evidence

The same prompt, response schema, model alias, four approved source excerpts, scoring and independent permission checks were retained. Model: OpenAI chat-latest; all 160 response records return chat-latest without a pinned underlying snapshot. There were 60 exact requests, 40 model-fallback source-interpretation requests and 20 controls in each arm. Each request text repeats an original pilot text five times under different request IDs. The mapping to original cases is preserved in repeat-map.json. Both arms use ADOM enforcement; this is a routing-efficiency comparison, not an ungated attack trial.

All 200 real ZIP packages were rechecked against expected selected files and original bytes, nested archives, manifest/evidence/source hashes, receipt hashes and saved copies. All 160 response usage records were reconciled against the spend ledger. Exact model proposals showed no mismatches in predicates, scope, cardinality or artifact names against the trusted request. Local rechecking is not third-party validation.

Ten baseline clarification cases proposed execution rather than asking for missing parameters. The shared validator rejected them before effects. Baseline denials passed; ADOM handled both clarification and denial cases correctly. Those errors remain in the raw records.

## Costs and caching

New estimated API cost: **$2.453985**. Carried prior spending: **$1.180975**. Combined authorized ledger: **$3.634960/$5**, leaving **$1.365040**. No additional API runs are implied. Prices are usage-based estimates, not an invoice reconciliation.

Cached input differs by arm: baseline legitimate input 329,840 tokens (57,600 cached), output 6,407; ADOM input 132,580 (48,000 cached), output 2,520. Repricing all input as uncached gives **59.89% savings**, still above 50%. Rate basis: [official model documentation](https://developers.openai.com/api/docs/models/chat-latest), $5/M input, $0.50/M cached input, $30/M output.

Latency includes routing/model preparation, network inference when invoked, local evidence checks and actual publication. It excludes common snapshot setup and subsequent scoring equally in both arms.

## Limits and reproduction

One release-package family, four source files, known authored request templates, one model alias, and one campaign. This supports repeatability on that workload; it does not establish broad unseen-task coverage, universal containment, or general superiority over ordinary automation. The model fallback remains an experimental campaign adapter rather than an automatically installed production feature.

The prior pilot and its raw records remain unchanged. Current preregistration, requests, gold, source snapshots, raw responses, all results, outputs, verification and ledger are preserved. Verify without more API calls:

```sh
PYTHONDONTWRITEBYTECODE=1 ../agentdojo-env/bin/python campaign.py analyze
PYTHONDONTWRITEBYTECODE=1 ../agentdojo-env/bin/python verify_saved.py
python3 repeat_summary.py
```

Do not run campaign.py run merely to verify: it is the paid execution entry point.
