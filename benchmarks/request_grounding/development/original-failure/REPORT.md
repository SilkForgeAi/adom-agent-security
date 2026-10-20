# ADOM request-to-contract grounding: bounded-language prototype

**The supported text-to-contract-to-IR-to-enforcement path is implemented. General arbitrary-request grounding is not solved.** The fixed evaluation missed its exact-task coverage and clarification targets. No failed case or criterion was removed.

## Implemented path

Authenticated request text and independent host grants/resources enter a whole-request recognizer. Recognized text derives the exact contract predicates, cardinality, source pins and output name; the host does not supply a task-kind label or expected contract. The executor retrieves a private parameterized IR or compiles the known exact graph locally, revalidates current evidence, and publishes through ADOM.

A cache miss for a supported exact contract does not require an LLM. Requests outside the verified language return MODEL_REQUIRED; recognized missing parameters return CLARIFY and failed authority returns DENY. There is no automatic model workaround for denied authority or invalid execution evidence. The parse trace records a syntactic derivation, not a proof of unrestricted natural-language meaning.

## Evaluation design

The challenge has 300 entries and 280 unique request texts across five families: plain exact, semantic interpretation, ambiguity/denial, exact-looking requests with additional material clauses, and detailed exact requests. The recognizer was frozen before text generation. The author designed both the grammar and challenge, so this is not an independently authored or genuinely blinded holdout. The runtime receives only request text and host context, never gold routes/contracts/selections.

## Results

| Measure | Outcome |
|---|---:|
| Routing agreement | 250/300 |
| False deterministic selections | 0/180 |
| Incorrect derived contracts on deterministic selections | 0 |
| Eligible exact tasks completed | 80/120 (66.7%) |
| Exact tasks unnecessarily escalated | 40/120 |
| Ambiguous requests correctly clarified | 20/30 |
| Effects on non-exact requests | 0 |
| New local compilations / IR reuses | 8 / 72 |
| Verified deterministic artifact latency p50 / p95 | 22.12 / 30.86 ms |
| API calls / new API spending | 0 / $0 |

The denominator for false deterministic selections includes all 180 model-required, ambiguous or denied cases. A wrong derived contract is also a failure even if the chosen route is deterministic and every downstream permission check would pass. The 80 selected exact tasks produced byte-verified source ZIPs, manifests and evidence. Reporting 80/80 execution correctness alone would hide the 40 eligible tasks the recognizer missed; full exact-task completion is 80/120.

## Confusion matrix

| Gold | Deterministic | Model required | Clarify | Deny | Review |
|---|---:|---:|---:|---:|---:|
| DETERMINISTIC | 80 | 40 | 0 | 0 | 0 |
| MODEL_REQUIRED | 0 | 120 | 0 | 0 | 0 |
| CLARIFY | 0 | 10 | 20 | 0 | 0 |
| DENY | 0 | 0 | 0 | 30 | 0 |
| REVIEW_REQUIRED | 0 | 0 | 0 | 0 | 0 |

## Recorded criteria

- PASS: zero_false_deterministic
- PASS: zero_wrong_derived_contracts
- FAIL: exact_coverage_at_least_70_percent
- FAIL: ambiguity_clarification_at_least_90_percent
- PASS: zero_nonexact_effects
- PASS: all_selected_exact_outputs_correct

**Combined support bar: NOT MET.** The recognizer was not expanded after viewing these outcomes. Historical results and frozen sources remain unchanged.

## What remains unresolved

1. Grounding is recognized controlled-language syntax, not arbitrary semantic interpretation. Unsupported exact paraphrases account for 40 unnecessary escalations. Ten incomplete requests were escalated instead of asking for clarification.
2. MODEL_REQUIRED is a handoff signal, not completed probabilistic reasoning. The 170 model-required outcomes were not executed by an LLM in this local phase. End-to-end utility, total API costs and p50/p95 latency for all 300 tasks are therefore unmeasured. No response or tool result was mocked to stand in for that missing branch.
3. A genuine independent unknown-request test is still missing. The independent_review/ packet specifies how an outside author can create and score one. This authored challenge and its correlated grammar/template variants cannot substitute for that evidence.
4. Timing covers parsing, contract binding, local compilation/lookup, evidence validation, packaging and fsynced publication on successful deterministic tasks. It excludes common input snapshot setup, independent verification and all unexecuted model work. No matched model baseline ran here, so the earlier savings percentages are not re-established.
5. The caller authenticates request origin and grants. Do not promote retrieved text or model output into the authenticated request merely because it matches the grammar. Identical strings from different origins require different authority outside this parser.
6. Python syntax evidence does not prove runtime program behavior or unrestricted user intent. This is the experimental in-process compiler/gateway profile, not the durable broker/receiver deployment or a universal escape-prevention system. Epoch/revocation/registry state is not durable across a fresh instance.

## Verification

```sh
PYTHONDONTWRITEBYTECODE=1 ../agentdojo-env/bin/python evaluate.py analyze
```

The verifier checks frozen code/data hashes, all derived contracts against scorer-owned expectations, actual source-package bytes, nested ZIPs, manifests, source pins, contract digests, evidence hashes and absence of additional artifacts. The corpus uses actual ADOM source snapshots, but the requests are constructed by the author. All raw requests, labels, results and packages are retained. Hash consistency is not independent validation.

## Installed opt-in integration

request_grounding.py, ground_request.py, test_request_grounding.py and request_grounding.md were added to ADOM as new files. Installed regression tests and an installed CLI smoke test passed. Existing applications do not automatically use the new route.
