# OpenAI Agents SDK (`openai-agents-python`) — Guardrail Coverage Across Handoffs and Hosted Tools

- **Upstream Repository:** `openai/openai-agents-python`
- **Pinned Commit:** `64fbde5d02b42ae5f9db668eb0184cdb3fc9d775` (`v0.24.0`, 2026-11-11)
- **Inspected Files:** `src/agents/run.py`, `src/agents/run_internal/tool_execution.py`, `src/agents/tool.py`
- **Reproduction Script:** `test_handoff_guardrail_repro.py`
- **Evidence Log:** `evidence/reproduction.log`

## What this shows

Both behaviors below are **documented** by OpenAI, not hidden bugs. The SDK's guardrails guide
states that input guardrails run only for the first agent in the chain, that tool guardrails run
on custom function-tool invocations, and recommends tool guardrails for workflows with handoffs.
This reproduction shows the consequence for a team that attaches agent-level input guardrails to
a handoff destination and expects them to run.

1. **A handoff destination's `input_guardrails` do not run** (`src/agents/run.py:1047-1051`, `1530-1542`, `1763-1827`, `2373`):
   - On turn 0 the runner evaluates `starting_agent.input_guardrails` (plus `run_config.input_guardrails`). After `handoff(destination_agent)`, `current_agent` becomes the destination, and its `input_guardrails` are not evaluated.
   - **Control:** `Runner.run(PrivilegedOps, ...)` directly raises `InputGuardrailTripwireTriggered` (`guard_calls == ["PrivilegedOps"]`, `executed == []`).
   - **Through a handoff:** `Runner.run(TriageAgent, ...)` then `transfer_to_privileged_ops` completes `wire_funds` with `guard_calls == []`.
   - OpenAI's recommended alternative for this case is tool guardrails on the function tools.
2. **Hosted and built-in tools have no tool guardrail fields** (`src/agents/run_internal/tool_execution.py:2794-2865`):
   - `LocalShellTool`, `ShellTool`, `ApplyPatchTool`, `HostedMCPTool` and `ComputerTool` expose no `tool_input_guardrails` / `tool_output_guardrails`; tool-guardrail dispatch wraps `FunctionTool` and client `MCPServer` tools.
3. **ADOM on the same input:**
   - `guarded_function_tool`, or `guard_openai_agent(triage, policy=...)` applied across the handoff tree (`test_05`), screens every `FunctionTool` call (unknown tools denied, raw and encoded taint blocked) whichever agent makes it, while allowing approved, untainted actions.
   - Like the SDK's tool guardrails, ADOM's wrapper covers function tools only. It does **not** cover the hosted and built-in tools in finding 2.

Filed upstream as a feature request: [openai/openai-agents-python#6087](https://github.com/openai/openai-agents-python/issues/6087) (opt-in destination-agent input guardrails after a handoff; open, no maintainer response as of 2026-11-19).

## How to Run

From the repository root (needs `git`, `bash`, `curl` and Python 3.11–3.13):

```bash
reproductions/run_reproduction.sh openai-agents
```

The script fetches `openai/openai-agents-python` at the pinned commit into `reproductions/.work/openai-agents`, checks the commit hash, installs it into its own virtualenv (`reproductions/.work/venv-openai-agents`) and runs the test. Nothing outside `reproductions/.work/` is installed or changed. To rerun the test afterwards:

```bash
reproductions/.work/venv-openai-agents/bin/python -m unittest -v reproductions/openai-agents-guardrail-reproduction/test_handoff_guardrail_repro.py
```

Expected output (`evidence/reproduction.log`): `Ran 5 tests — OK`.

## Defensive Remediation

- Evaluate `new_agent.input_guardrails` when processing `NextStepHandoff` (or attach invariant capability/action screening directly at tool execution time rather than relying solely on entry-agent guardrails).
- Expose tool-boundary hooks uniformly across hosted and shell tool descriptors, not only local `FunctionTool` instances.
