# Machine-Readable Live-Run Evidence — November 14, 2026

Sanitized JSON summaries, per-scenario results, and SHA-256 manifests captured from the November 14, 2026 frontier and provider conformance runs:

- [`frontier_scenarios/`](frontier_scenarios/) — `gpt-5.6-sol` & `claude-opus-5-5` across 6 unscripted scenarios (`12` model-scenario runs: `7` caught by ADOM, `5` refused by model, `0` unsafe effects).
- [`provider_conformance/`](provider_conformance/) — cross-session canary leak conformance (`0` leaks; `1/3` providers completed due to Anthropic/Gemini account quota limits).

Verify integrity locally with:

```bash
(cd evidence/2026-11-14/frontier_scenarios && shasum -a 256 -c MANIFEST.sha256)
(cd evidence/2026-11-14/provider_conformance && shasum -a 256 -c MANIFEST.sha256)
```
