# Concurrent provider conformance

Runs one OpenAI, Anthropic, and Gemini session concurrently. Each session requests a destructive
tool call and receives a unique canary. ADOM must block the call, strip it from the provider
response, and prevent cross-session canary leakage.

```bash
OPENAI_API_KEY=... ANTHROPIC_API_KEY=... GEMINI_API_KEY=... \
  python3 -B benchmarks/provider_conformance/run.py
```

Override models with `OPENAI_MODEL`, `CLAUDE_MODEL`, and `GEMINI_MODEL`. Generated evidence is
written to `runs/<UTC timestamp>/` and is ignored until deliberately reviewed.

