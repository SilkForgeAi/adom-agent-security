# NVIDIA NeMo Guardrails — Tool-Call Regex Fail-Open, Encoding Bypass, Secret-Filter Crash, & IORails Parser Scope

- **Upstream Repository:** `NVIDIA-NeMo/Guardrails`
- **Pinned Commit:** `5d7f4c1ca62fb6155066e6c581379d1a5ec11338` (`v0.25.0-rc1`, 2026-11-13)
- **Inspected Files:**
  - `nemoguardrails/library/regex/actions.py`
  - `nemoguardrails/actions/validation/filter_secrets.py`
  - `nemoguardrails/guardrails/model_engine.py`
  - `nemoguardrails/guardrails/tool_schema.py`
- **Reproduction Script:** `test_tool_call_regex_and_secrets_repro.py`
- **Evidence Log:** `evidence/reproduction.log`

## Verified Findings

1. **Fail-open default when a tool is absent from `regex_detection.tool_call`** (`nemoguardrails/library/regex/actions.py:153-162`):
   - **Control:** Configured `send_email` carrying raw `AKIAIOSFODNN7EXAMPLE` returns `RailDecision.BLOCK`.
   - **Bypass:** Tool `http_post` (present in `Toolset`, absent from `regex_detection.tool_call`) carrying the identical raw AWS key returns `RailDecision.ALLOW` (`detections == []`), diverging from sibling fail-closed behavior in `evaluate_tool_call_cel` (`cel/actions.py:48`).
2. **Encoded payloads bypass configured tool regexes:**
   - Even when `send_email` has `AKIA[0-9A-Z]{16}` configured, `base64`, `hex`, and reversed variants return `RailDecision.ALLOW` (`json.dumps` without canonical decoding).
3. **Broken `detect-secrets` integration in `filter_secrets.contains_secrets`** (`filter_secrets.py:30`):
   - Calls `detect_secrets.scan_adhoc_string(resp)`, raising `AttributeError: module 'detect_secrets' has no attribute 'scan_adhoc_string'` on `detect-secrets==1.5.0`.
4. **IORails `ModelEngine` silently falls back to OpenAI Chat parser** (`model_engine.py:1429-1474`):
   - `extract_latest_tool_calls`, `extract_tool_results`, and `extract_tool_exchanges` fall back to `_extract_tool_results_openai` / `_latest_tool_calls_openai`, returning `[]` on Anthropic `/v1/messages` `tool_use` / `tool_result` content blocks.
5. **Side-by-Side ADOM Behavior:**
   - `ModelProxyPolicy(strict_deny_unknown=True)` fails closed on unconfigured `http_post`, blocks `raw`, `base64`, `hex`, and reversed AWS/canary payloads on `send_email`, and allows benign approved internal operations (`get_status`) without flagging.

## How to Run

From the repository root (needs `git`, `bash`, `curl` and Python 3.11–3.13):

```bash
reproductions/run_reproduction.sh nemo-guardrails
```

The script fetches `NVIDIA-NeMo/Guardrails` at the pinned commit into `reproductions/.work/nemo-guardrails`, checks the commit hash, installs it into its own virtualenv (`reproductions/.work/venv-nemo-guardrails`) and runs the test. Nothing outside `reproductions/.work/` is installed or changed. To rerun the test afterwards:

```bash
reproductions/.work/venv-nemo-guardrails/bin/python -m unittest -v reproductions/nemo-guardrails-tool-policy-reproduction/test_tool_call_regex_and_secrets_repro.py
```

Expected output (`evidence/reproduction.log`): `Ran 6 tests in 0.049s — OK`.

## Defensive Remediation

- Fail closed (or enforce a global default pattern set) in `detect_tool_call_regex_pattern` when a tool lacks a per-tool override.
- Normalize nested JSON/string arguments across common encodings (`base64`, `hex`, URL-encoding, reversed strings) before regex matching.
- Replace `detect_secrets.scan_adhoc_string` with the `detect-secrets` `SecretsCollection` / plugin scanner API and register explicit provider extractors instead of silently falling back to OpenAI Chat Shapes.
