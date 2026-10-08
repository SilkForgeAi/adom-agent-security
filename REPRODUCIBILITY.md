# Reproducibility

## Evidence levels

The repository separates four different claims instead of combining them into one score:

1. Deterministic state-machine replay.
2. Docker network-topology and service-effect replay.
3. Live-model action harnesses whose outputs vary by model and run.
4. Historical reports retained for provenance but not treated as sealed evidence.

## Deterministic replay

```bash
python3 -B incident_replay/run_all.py
```

Expected terminal verdict: `INCIDENT REPLAY: ALL VERIFIED`.

## Container replay

```bash
python3 -B incident_replay/container_lab/run_lab.py
```

Expected terminal verdict: `VERDICT: VERIFIED`. The run recreates the service-owned evidence and
manifest, then tears down the topology. No API key or Internet access is required.

## Verify committed bytes

```bash
sha256sum -c incident_replay/MANIFEST.sha256
sha256sum -c incident_replay/container_lab/MANIFEST.sha256
```

## Live providers

Live harnesses require separately funded provider keys. They do not retry automatically and do not
count errors, provider refusals, or missing actions as passes. Never commit `.env` or generated
`runs/` directories without reviewing them.

```bash
OPENAI_API_KEY=... ANTHROPIC_API_KEY=... GEMINI_API_KEY=... \
  python3 -B benchmarks/provider_conformance/run.py

OPENAI_API_KEY=... ANTHROPIC_API_KEY=... GEMINI_API_KEY=... \
  python3 -B benchmarks/frontier_scenarios/run.py
```

Each upgraded harness writes sanitized JSON plus `MANIFEST.sha256` below its ignored `runs/`
directory. Raw provider responses and credentials are intentionally not persisted.

## Reporting a reproduction

Record the commit SHA, OS, architecture, Docker version, Python version, exact command, verifier
output, and manifest check. A failure is valuable evidence; do not silently modify the policy or
fixture until it passes.


## Newer aggregate summaries

The [October 8 summaries](evidence/2026-10-08/README.md) cover later local workflow-lab
and AgentDojo snapshots. Their matching harnesses and raw episodes are not shipped in this
reference repository. The public replay commands above do not reproduce those experiments.

Verify the published summary bytes with:

```bash
sha256sum -c evidence/2026-10-08/MANIFEST.sha256
```

On macOS, use `shasum -a 256 -c` if `sha256sum` is unavailable. This verifies bytes only;
it does not rerun the experiment, establish truth, or replace external reproduction. See
[results](docs/RESULTS.md) for configuration, missing cases, clean gates and scoring limits.
