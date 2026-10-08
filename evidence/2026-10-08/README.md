# Aggregate evidence summaries — October 8, 2026

These JSON files publish selected counts extracted from the author-retained records. They are historical summaries, not fresh reruns or independent certification.

- `agentdojo_v6_summary.json`: native aggregate counts, denominators, partial completion and qualification limits. Source audit tables are copied with missing episode names replaced by a count. The matched Workspace subset comes from the dated review, not the all-560 baseline table.
- `worker_stop_summary.json`: aggregate counts from 2,000 worker records, ready/check statuses and the recorded timing distributions. Container environments, host paths and individual records are omitted.
- `MANIFEST.sha256`: hashes of the published summary files and this explanation. Hashes of the retained original records are inside each summary. Those originals are not included here; their hashes identify review artifacts and do not authenticate the results or reproduce them.

The subsequent [AgentDojo reproducibility package](../../benchmarks/agentdojo/README.md) publishes the frozen v6 adapter dependency subset and all 320 banking episode/trace pairs, with free verification and offline native rescoring. The original JSON summaries remain unchanged as dated publication records, including their original availability statements. Other suite raw records, later corrections and workflow-lab source remain outside this package. No unaffiliated reproduction is claimed. See [results](../../docs/RESULTS.md), [engineering status](../../docs/ENGINEERING_STATUS.md), and [reproducibility](../../REPRODUCIBILITY.md).
