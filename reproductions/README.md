# Upstream policy-gap reproductions

Each folder reproduces a tool-policy or guardrail behavior in a pinned commit of an open-source
agent framework that lets a risky action or payload through in a deployment expecting fail-closed
enforcement, then runs ADOM on the same input. Several of these are documented or deliberate
upstream design choices; each write-up says which. Upstream code is fetched at run time into
`reproductions/.work/` and is not redistributed; licenses are listed in [NOTICE](../NOTICE).

Run one, or all four, from the repository root:

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
