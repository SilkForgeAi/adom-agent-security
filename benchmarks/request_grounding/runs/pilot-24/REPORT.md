# ADOM live request grounding pilot — 2026-10-20

## Result

The frozen pilot criteria all passed. This is a bounded, author-created development result, not independent validation or arbitrary-request grounding.

| Measure | Always model + shared enforcement | ADOM routing + model fallback |
|---|---:|---:|
| Legitimate task completion | 20/20 | 20/20 |
| Exact tasks | 12/12 | 12/12 |
| Source interpretation tasks | 8/8 | 8/8 |
| Clarification / denial controls | 2/4 | 4/4 |
| All outcomes correct | 22/24 | 24/24 |
| API calls, all cases | 24 | 8 |
| Estimated API cost, legitimate tasks | $0.310680 | $0.090020 |
| Estimated cost per successful legitimate task | $0.015534 | $0.004501 |
| All-case API cost | $0.380485 | $0.090020 |
| Legitimate-task latency median | 1472.42 ms | 45.20 ms |
| Legitimate-task latency p95 | 1759.83 ms | 1597.60 ms |
| Authority violations / unexpected control effects | 0 / 0 | 0 / 0 |

Cost per successful legitimate task fell 71.02%; median latency fell 96.93%. The p95 improved about 9.22%, a much smaller tail-latency benefit. All 20 legitimate outcomes in each arm are included in timing and cost denominators. Failure/control costs are reported separately rather than used to inflate the legitimate-task savings.

The criteria, frozen before calls, were no lower legitimate success, zero authority violations, at least 50% legitimate cost-per-success savings, at least 50% median latency savings, and no worse p95. This run passes each. It does not establish a general breakthrough.

## What actually ran

24 requests × 2 arms, randomized interleaving, 32 real OpenAI API calls to chat-latest, no retries. The API returned model identifier chat-latest, so a stable underlying snapshot is unavailable. Twelve exact requests and four controls came from the inspected development corpus. Eight source-interpretation requests were authored for this pilot: four code-behavior questions, each used with two output names. These are correlated cases, not eight independent capabilities or a blinded holdout.

ADOM handled 12 exact tasks plus four controls without inference. All eight source-interpretation requests went through the live model branch. The model received identical request/context/source-excerpt payloads in both arms and proposed bounded syntax predicates, source scope and output names. Host code checked independent authority, validated the contract and actual source facts, and executed the known DAG through the existing ADOM gateway. A model proposal never became an authenticated user request or a new source of authority.

This live fallback is implemented in campaign.py as an experimental adapter. It is not automatically installed as a production fallback in every ADOM application. Both arms share enforcement, so this comparison measures routing efficiency and task outcomes; it is not an ungated-versus-contained attack trial.

## Failures retained

The always-model arm failed both clarification cases. It proposed execution with an invented destination and/or incomplete predicates. The validator rejected these proposals before effects. These are failed control responses, not successful harmful actions. ADOM requested clarification for both. No failure was retried or removed.

## Verification and costs

verify_saved.py rechecked all 40 real ZIP artifacts against scorer-owned expected selections, original source bytes, manifests, nested source archives, evidence hashes, receipt hashes and source pins. It checked all 32 response usage records against the ledger and verified that model proposals on exact tasks preserved the expected requirements, cardinality, scope and output. No exact-task contract mismatches were found. This is a second local verification pass, not independent third-party review.

New API spending estimated from returned usage: **$0.470505**. Prior authorized campaign spending: **$0.710470**. Combined ledger: **$1.180975 of $5**, leaving **$3.819025** under that cap. No new spending allowance is implied.

Prompt caching affects pricing: legitimate baseline input 65,922 tokens (12,800 cached), output 1,289; ADOM input 26,500 (12,800 cached), output 504. Repricing all input as uncached gives **59.92%** savings, still above the 50% target. These are API estimates, not an invoice reconciliation. Rates checked against [official OpenAI documentation](https://developers.openai.com/api/docs/models/chat-latest): $5/M input, $0.50/M cached input, $30/M output.

Latency starts before routing/model preparation and ends after execution or the returned decision. It includes network inference and actual local publication; common snapshot setup and independent scoring are excluded from both arms. Warm-process registry reuse is included. Small-sample p95 and network timing are variable and require repeated campaigns before broad claims.

## Boundaries

One release-package workflow family, four ADOM source files, 24 authored requests, one model alias, one run. Source excerpts were sent with explicit user approval. No credentials were included in payloads. The system still does not prove arbitrary natural-language intent, runtime code safety, universal escape prevention or general superiority over ordinary automation. A wider independently authored test and repeated matched runs remain necessary.

## Recheck without API calls

```sh
PYTHONDONTWRITEBYTECODE=1 ../agentdojo-env/bin/python campaign.py analyze
PYTHONDONTWRITEBYTECODE=1 ../agentdojo-env/bin/python verify_saved.py
```

Do not run campaign.py run to verify: that is the paid execution entry point and requires a fresh ledger. Frozen preregistration, raw API requests/responses, all results including errors, source snapshots, output artifacts, analysis and spend ledger are retained here.
