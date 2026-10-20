# Selective inference with ADOM: live evidence and executable harness

**Within this supported release-package workflow, ADOM preserved task completion while reducing model calls and cost.** This author-run study is not AgentDojo, independent validation, or arbitrary natural-language grounding.

| 100 legitimate tasks per arm, plus 20 controls | Always model + shared enforcement | ADOM routing + live fallback |
|---|---:|---:|
| Legitimate task completion | 100/100 | **100/100** |
| Exact tasks / source-interpretation tasks | 60/60 / 40/40 | 60/60 / 40/40 |
| Controls handled correctly | 10/20 | **20/20** |
| Model API calls, including controls | 120 | **40** |
| Estimated API cost per successful legitimate task | $0.015822 | **$0.005225** |
| Median legitimate-task latency | 1,426.18 ms | **32.49 ms** |
| p95 legitimate-task latency | 2,064.65 ms | **1,845.45 ms** |
| Unauthorized effects | 0 | 0 |

**66.98% lower cost per success; 97.72% lower median latency.** The aggregate p95 improved 10.62%, but ADOM's p95 was slower in two of the five repetitions. All 200 packages were checked against source bytes, manifests and evidence hashes. Repricing all input as uncached yields 59.89% cost savings. Rates and token accounting appear in the full reports.

The 100-task arm repeats the original 20 legitimate requests five times, with fresh identities and actual outputs. It contains **100 task executions, not 100 distinct semantic tasks**. The four control requests also repeat five times. Repetitions were randomized and interleaved, using warm registries; these are not independent cold starts. Model: OpenAI's moving `chat-latest` alias, with no stable underlying snapshot returned. All errors are retained.

## Read the evidence

- [100-task-per-arm report](runs/repeat-120/REPORT.md), [raw results](runs/repeat-120/results.json), [metrics](runs/repeat-120/analysis.json), [per-repetition metrics](runs/repeat-120/repeat-analysis.json), [usage ledger](runs/repeat-120/spend.json).
- [Original 20-task-per-arm live pilot](runs/pilot-24/REPORT.md), [pilot raw results](runs/pilot-24/results.json).
- [Original failed grounding evaluation](development/original-failure/REPORT.md) and [V2 regression rerun](development/v2-regression/REPORT.md). Original coverage was 80/120 and clarification 20/30; after repairing known syntax gaps the same inspected corpus reached 120/120 and 30/30. This is regression evidence, not a fresh holdout.

The two baseline clarification failures repeat across all five rounds: the model proposed execution for an incomplete request. **The shared validator rejected the proposals before any effect.** Both arms use ADOM enforcement, so this study measures inference routing and outcome quality, not incremental containment over an unprotected baseline. The supported model fallback is the experimental campaign adapter, not a production feature automatically installed in every ADOM application.

## Verify saved evidence — no API key or third-party packages

From the repository root, with Python 3.10+:

```bash
python3 -B benchmarks/request_grounding/verify.py
```

The standard-library verifier checks all published file hashes, 288 saved executions across both live campaigns, 192 API response usage records, 240 actual output packages, source bytes, contract/receipt/evidence hashes, task scores, reported cost/latency aggregates, and ledger totals. It checks captured evidence consistency; this is not an independent rerun or a proof that provider receipts cannot be fabricated by an author.

Run 68 local regression tests against the isolated published dependency snapshot:

```bash
cd benchmarks/request_grounding/tests
python3 -B -m unittest test_request_grounding_v2.V2Tests test_parameterized_workflow test_workflow_compiler -q
```

The snapshot under `vendor/adom/` is the runtime exercised in these experiments, isolated from the older reference core at repository root. It includes only the dependencies necessary for this experiment. Publication testing found that the historical import-time freeze omitted the lazy-loaded `read_observation.py` dependency. That file is included and pinned at publication, not retrospectively claimed as pre-run frozen. Its non-read passthrough path is exercised by the release-bundle tests. It does not change the public core's current behavior or publish the private AgentDojo/workflow-lab checkout.

## Optional fresh live rerun — spends API credits

Set `OPENAI_API_KEY` yourself. Start with the smaller original pilot. New output must be outside this evidence directory and must not exist:

```bash
python3 -B benchmarks/request_grounding/rerun.py \
  --run pilot-24 --output /tmp/adom-fresh-pilot \
  --budget-usd 1 --allow-paid-run
```

For the 100-legitimate-task arm, use `--run repeat-120` with a sufficient budget. The recorded original campaign cost $2.45 total for both arms, but future costs and latency vary with caching and the moving model alias. The transport reserves a conservative upper bound before each API call, stops on uncertainty without paid retries, and enforces the supplied cap (maximum $5 per invocation). The API key is used only as an authorization header and is not written to records. A cap-induced stop is an incomplete run, not a passing result.

For an offline preparation check, pass `--prepare-only`; no key is needed and no API call is made. The runner creates new source/request snapshots and records its configuration. It preserves all historical records.

## What was changed for publication

Credentials, private environment files, unrelated working files, and absolute author filesystem paths are excluded. The allowlisted API requests/responses contain the four source excerpts necessary to inspect the experiment. API response IDs and usage are retained; authorization headers are not.

The measured preregistrations are retained as `measured-preregistration.json`, with author paths deidentified. `runtime-manifest.json` separately pins the relocated runnable export; it must not be confused with the pre-run freeze. The model prompt, schemas, routing, enforcement and scoring logic were not tuned for publication. Edits relocate imports, use explicit environment credentials for new runs, and prevent historical output overwrite. [Publication provenance](publication-provenance.json) records measured and exported file hashes.

These results establish repeatable performance on a known authored workflow family. Broader independently authored holdouts, additional workflows/models, and external reproduction remain future work. Syntax evidence does not prove runtime safety or unrestricted user intent; this in-process profile is not universal escape prevention or durable OS containment.
