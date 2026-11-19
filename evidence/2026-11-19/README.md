# ADOM on a real Kong AI Gateway — November 19, 2026

`kong_konnect/` holds the first run of ADOM's generated Kong config on a real Kong Gateway
Enterprise data plane (3.16, licensed through Kong Konnect), produced by
`deployment/kong-konnect-smoke/run.sh`. The model upstream is a local mock; no real model,
API key or customer data was involved.

## Results

| Check | Result |
|---|---|
| Kong accepts ADOM's decK config | PASS (after fixing `metrics.block_details` → `block_detail`, which the first run surfaced: Kong rejected it with "validation error: unknown field") |
| Benign request passes | PASS (200) |
| Secret in the model's reply is blocked | PASS (Kong returned 400 with ADOM's message; the key never reached the client) |
| 40 benign requests from unidentified callers | PASS (none blocked; no shared breaker) |
| Guardrail called on INPUT and OUTPUT | PASS (89 calls: 45 INPUT, 44 OUTPUT) |
| No unrendered `$(...)` values reached ADOM | PASS (every body was exactly `{source, text}`) |
| Reply that is only a tool call (content null) | LIMIT: reached the client. Kong made **no OUTPUT guardrail call** for it, so no guardrail config can see it |
| Secret read by a tool, echoed base64 in the reply | LIMIT: reached the client. Kong's `$(content)` included the tool output text on INPUT, but merged with user text and unlabeled, so ADOM learned no taint from it |

## Scope of the PASS rows

The blocked secret was a raw AWS-shaped key, caught by ADOM's generic secret patterns. As
shipped, `adom kong-guard` does not catch encoded secrets on this plane (it decodes only values
configured as taints, and the CLI has no option for them). See
[`docs/KONG_AI_GATEWAY_ARCHITECTURE.md`](../../docs/KONG_AI_GATEWAY_ARCHITECTURE.md).

## What Kong actually sends

`guardrail_requests.jsonl` records every call Kong made to the guardrail (via a capture proxy).
With `text_source: concatenate_all_content`, the body is `{"source": "INPUT"|"OUTPUT", "text": ...}`
and nothing else; the text joins message contents newest first, including `role: "tool"`
messages. Kong sends no caller identity (`User-Agent: lua-resty-http`), so every call was an
unidentified session.

## Verify

```bash
(cd evidence/2026-11-19/kong_konnect && sha256sum -c MANIFEST.sha256)
adom verify-chain evidence/2026-11-19/kong_konnect/decisions.jsonl   # ADOM's own audit chain: 89 records
```

Reproduce with your own Konnect account: `deployment/kong-konnect-smoke/run.sh`.
