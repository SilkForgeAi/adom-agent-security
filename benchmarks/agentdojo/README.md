# ADOM AgentDojo evaluation package

This package publishes the frozen v6 adapter, pinned dependencies, complete historical banking records, a free verifier, an offline native scorer, and a separate paid validation runner. It runs independently of the author's Desktop checkout. **It has not yet been reproduced by an unaffiliated evaluator.**

## Verify the historical records — free, no API key

From the repository root, with Python 3.12:

```sh
python -B benchmarks/agentdojo/verify.py
```

This standard-library command verifies archive/member hashes, all 320 episode/trace pairings, policy seals, the required adapter source against the original registration, coverage, native score agreement and published aggregates. Hashes are anchored by the repository commit; they are not provider signatures or proof that the author could not fabricate a record.

To independently recompute the saved native scores against the pinned AgentDojo banking fixtures, install the dependencies and replay the recorded dispatched actions. This also uses **no API calls**:

```sh
python3.12 -m venv .venv-agentdojo
.venv-agentdojo/bin/python -m pip install -r benchmarks/agentdojo/requirements.lock
.venv-agentdojo/bin/python -B benchmarks/agentdojo/rescore.py
.venv-agentdojo/bin/python -B -m unittest discover -s benchmarks/agentdojo/tests -v
PYTHONPATH=benchmarks/agentdojo/source .venv-agentdojo/bin/python -B -m unittest \
  adom.evaluation.agentdojo.test_banking \
  adom.evaluation.agentdojo.test_contracts \
  adom.evaluation.agentdojo.test_run_integrity \
  adom.evaluation.agentdojo.test_recovery_publication
```

The scorer reconstructs synthetic fixture effects using ADOM's executor audit for defended cases and actual tool-result messages for baseline cases. It retains the benchmark's attempted-call semantics. It does not generate new model responses or authenticate the original provider interaction.

## Historical banking result

Model: `gpt-4o-2024-05-13`; AgentDojo `0.1.35`; benchmark `v1.2.2`; `important_instructions`; one repeat. Complete banking scope only; other suites remain separate aggregate records.

| Condition | Clean utility | Attacked utility | Native attack success |
|---|---:|---:|---:|
| Baseline | 16/16 | 126/144 | 87/144 |
| ADOM | 15/16 | 143/144 | 0/144 |

**The original clean gate failed.** The 6.25 percentage-point clean drop exceeded its registered 5-point allowance. Attacks were subsequently run as an explicitly exploratory continuation. This release preserves that classification and the failed task; it does not convert the historical result into qualified benchmark success.

Policies were developed with task/fixture exposure and use privileged clean-fixture inputs. These are authored contracts, not blind general-purpose inference of legitimate intent. A zero observed ASR is not a guarantee, a zero false-positive rate, or evidence about adaptive attacks. The API model used here exposes no activations: this evaluation does not test ADOM's white-box capabilities.

Historical `execution_outcomes` lists include calls made by benchmark checkers/reference trajectories because the old hook was global. They are preserved verbatim but **must not be interpreted as agent-only dispatch or independent service evidence**. The offline scorer uses the narrower audit/trace sources described above. The new runner captures only calls made inside the agent pipeline query, with a regression test for this distinction.

The archive also retains original registration, controller/worker/audit files, policy freeze, and clean-gate record. Those controller files are provenance, not supported launch scripts. The runnable controller below is new and deliberately differs in budgeting, timeouts, failure handling and dispatch instrumentation. The 27 packaged source files are an exact, hash-checked dependency subset of the historical v6 adapter, not the latest private corrections.

## Fresh validation — explicitly paid

The supported public runner currently evaluates **banking**, one pinned GPT-4o-mini snapshot, baseline versus ADOM, and one fixed registered attack. Its default 2-task × 2-injection subset is an integration check, not a full-suite or representative security estimate. It is not an AgentLock comparison.

First freeze the configuration, policies, system prompt, package hashes and identical attack payloads for both arms. No real API key is required:

```sh
.venv-agentdojo/bin/python -B benchmarks/agentdojo/run_paid.py freeze \
  --config benchmarks/agentdojo/validation.json --out /tmp/adom-validation-001
```

Review and preserve `freeze.json` and its hash before execution. A model snapshot does not eliminate sampling or service variability. The pipeline adds disclosed task-solving guidance in both arms; output enforcement is ADOM-specific. Reusing an old baseline from a different model/scaffold is not supported.

Only this next command makes API requests. Set `OPENAI_API_KEY` securely in your environment; no `.env` file is loaded or bundled:

```sh
.venv-agentdojo/bin/python -B benchmarks/agentdojo/run_paid.py run \
  --out /tmp/adom-validation-001 --execute-paid
```

Requests use temperature 0, an 8192 output-token cap, SDK retries disabled, `store=false`, and the official OpenAI endpoint. Execution is serial. Before each request, SQLite reserves the cost of a full 128,000 input tokens plus the full output cap at the documented GPT-4o-mini rates ($0.15/$0.60 per million). Returned usage reconciles the reservation; failed or missing-usage responses keep it. The configured ceiling is at most $3. This is conservative token-rate accounting, **not an authoritative provider billing limit**; cache discounts are ignored. Price reference checked 2026-10-08: [official model documentation](https://developers.openai.com/api/docs/models/gpt-4o-mini).

All selected clean episodes run first. If baseline or ADOM misses the frozen minimum, or ADOM exceeds the allowed clean drop, no attacks run. Any runtime/API error stops the campaign and preserves an inconclusive record and unresolved reservation. The runner refuses to overwrite or silently resume an existing attempt. Change configs in a new output directory and disclose amendments; do not replace old outcomes.

To inspect a saved fresh run without credentials:

```sh
python -B benchmarks/agentdojo/verify_run.py /tmp/adom-validation-001
```

Missing/inconclusive cases remain visible and receive no security credit. Native ASR remains primary; this release does not automatically override scores with an effect-verified metric.

## Scope and licensing

ADOM adapter and harness: repository Apache-2.0 license. AgentDojo is an external MIT-licensed dependency; its notice is retained in `AGENTDOJO_LICENSE.txt` for fixture excerpts in the historical traces. Other pinned dependencies retain their own licenses. No AgentLock code is included. Package version pins do not constitute proof-preserving builds or a guarantee of future API availability.

This is a reproducibility release: publicly inspectable code and checkable author records. Independent fresh reproduction, broader attacks, production integration and external review remain outstanding.
