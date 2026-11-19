# Superagent (`safety-agent`) — Missing-Classification Default & Empty-Text PDF Handling

- **Upstream Repository:** `superagent-ai/superagent`
- **Pinned Commit:** `c9e646271bf15cf7ea7b8e2de9de98008ea1099d` (2026-08-25)
- **Inspected File:** `sdk/python/src/safety_agent/client.py`
- **Reproduction Script:** `test_guard_fail_open_repro.py`
- **Evidence Log:** `evidence/reproduction.log`

## What this shows

Behaviors of the pinned commit, found by reading `client.py` and confirmed by the tests below.
Whether they are intended is for the Superagent maintainers to say; they are listed because each
lets content pass unclassified in a deployment that expects fail-closed screening.

## Verified Findings

1. **Missing `"classification"` key silently defaults to `"pass"`** (`client.py:281-287`, `_guard_image` at `341`):
   - **Control:** Provider JSON containing `"classification":"block"` returns `GuardResponse.classification == "block"`.
   - **Missing key:** Valid provider JSON omitting `"classification"` (e.g., `{"violation_types":["exfiltration"],"reasoning":"secret exfil detected"}`) returns `classification == "pass"` via `parsed.get("classification", "pass")`.
2. **PDFs with zero extractable text auto-pass without vision/OCR inspection** (`client.py:414-427`):
   - When `process_input` yields `ProcessedInput(type="pdf", pages=["   ", "\n"])` (such as scanned/image-only PDFs carrying rendered prompt-injection text), `guard()` immediately returns `classification="pass"` (`"PDF contains no extractable text content to analyze."`).
3. **Zero-overlap chunking** (`_chunk_text`, `client.py:38-70`):
   - Long inputs split cleanly at space boundaries with zero token/character overlap across chunks.
4. **Side-by-Side ADOM Behavior:**
   - Because ADOM enforces policy deterministically at tool/egress execution (`ModelProxyPolicy`) after `note_read(...)`, missing/skipped upstream document classifiers do not permit exfiltrating tainted or encoded secrets (`base64`, `hex`, reversed) on downstream tool calls.

## How to Run

From the repository root (needs `git`, `bash`, `curl` and Python 3.11–3.13):

```bash
reproductions/run_reproduction.sh superagent
```

The script fetches `superagent-ai/superagent` at the pinned commit into `reproductions/.work/superagent`, checks the commit hash, installs it into its own virtualenv (`reproductions/.work/venv-superagent`) and runs the test. Nothing outside `reproductions/.work/` is installed or changed. To rerun the test afterwards:

```bash
reproductions/.work/venv-superagent/bin/python -m unittest -v reproductions/superagent-guard-failopen-reproduction/test_guard_fail_open_repro.py
```

Expected output (`evidence/reproduction.log`): `Ran 5 tests in 0.391s — OK`.

## Defensive Remediation

- Fail closed (`"block"` or explicit error/review state) when `"classification"` is missing or invalid in provider output.
- Route PDFs with empty extracted text to vision/OCR rendering rather than returning `"pass"`, and pair prompt-level scanning with deterministic downstream action/egress enforcement.
