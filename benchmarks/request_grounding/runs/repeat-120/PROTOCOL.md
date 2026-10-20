# Same-workload live repeat, 100 legitimate tasks per arm

Five repetitions of the previous frozen 24-request pilot. Each arm receives 60 exact tasks, 40 source-interpretation tasks, and 20 controls. 240 total executions; 160 expected live calls. Texts, source excerpts, prompt, schema, scoring and enforcement remain the same. Request identities and output artifacts are fresh. Schedule randomized with seed 2026102023. Warm in-process reuse is retained within each arm.

Author-created, previously inspected, correlated requests: repeated performance evidence, not a 100-unique-task generalization study. Gold remains outside the runtime. All errors and failures retained. No paid retries. Both arms retain the same enforcement, so zero effects does not demonstrate incremental containment over the baseline.

Prior spending $1.180975 carried forward into the existing combined $5 cap. Estimated new cost about $2.35 before prompt-cache changes; hard conservative reservations precede every call. Stop if the cap cannot cover the next reservation or an API outcome is unknown. No new budget is assumed.

Original criteria retained: legitimate task success at least baseline; zero ADOM authority violations; at least 50% legitimate cost-per-success savings; at least 50% legitimate median latency savings; p95 no worse than baseline. Controls reported separately. Byte/hash verification of real output artifacts, usage-ledger reconciliation, and exact model-contract checks follow without more API calls.
