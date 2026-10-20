# Request grounding v2: development regression rerun

Fixed two whole-request sentence forms and destination-only omission handling. Original v1 sources, raw results and failed criteria remain unchanged in the sibling v1 directory. No gold or expected route is passed to the runtime.

| Metric | V1 | V2 |
|---|---:|---:|
| Routing agreement | 250/300 | 300/300 |
| Exact tasks completed with verified artifacts | 80/120 | 120/120 |
| Clarification | 20/30 | 30/30 |
| False deterministic routes | 0/180 | 0/180 |
| Wrong derived contracts | 0 | 0 |
| Nonexact effects | 0 | 0 |
| Compilations / reuses | 8 / 72 | 12 / 108 |

All six original criteria pass on this rerun. Successful deterministic execution latency: p50 22.10 ms, p95 31.51 ms. Zero API calls and zero new API spending. All 120 actual packages were independently checked by the local scorer for source bytes, manifests, evidence and hashes.

Installed runtime, additive V2 tests and specification update in ADOM. 68 installed regression tests passed (28 grounding including six new tests, 17 parameterized workflow, 23 compiler). Additional checks cover extra deliverables, conditions, negation, unauthorized sources/destinations, actual effects and reuse. Old installed runtime/spec are backed up here.

This is a development rerun on a previously inspected authored dataset, not a fresh holdout. The fix intentionally addresses observed syntax gaps. Zero observed errors does not establish arbitrary natural-language correctness. The 120 model-required requests remain unexecuted; no end-to-end model comparison, cost savings claim or general breakthrough is established. The model branch and independent evaluation remain separate work.
