# Upstream bypass reproductions

Each folder reproduces a tool-policy or guardrail bypass in a pinned commit of an open-source
agent framework, then runs ADOM on the same input. Run one, or all four, from the repository
root:

```bash
reproductions/run_reproduction.sh openai-agents     # openai/openai-agents-python @ 64fbde5
reproductions/run_reproduction.sh nemo-guardrails   # NVIDIA-NeMo/Guardrails @ 5d7f4c1
reproductions/run_reproduction.sh snyk-agent-scan   # snyk/agent-scan @ 6eb2125
reproductions/run_reproduction.sh superagent        # superagent-ai/superagent @ c9e6462
reproductions/run_reproduction.sh all
```

Needs `git`, `bash`, `curl` and Python 3.11–3.13 (NeMo Guardrails requires <3.14; pick an
interpreter with `PYTHON=python3.12`). Each target gets the exact upstream commit (checked by
hash) and its own virtualenv under `reproductions/.work/`, which git ignores. No API keys or
network access beyond GitHub and PyPI are needed; the tests use local mocks.

The LiteLLM and OpenHands reproductions live in their own repositories, linked from the main
README.
