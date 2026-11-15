# OpenAI Agents SDK (`openai-agents-python`) — Handoff Guardrail Bypass & Native Tool Coverage Gap

- **Upstream Repository:** `openai/openai-agents-python`
- **Pinned Commit:** `64fbde5d02b42ae5f9db668eb0184cdb3fc9d775` (`v0.24.0`, 2026-11-11)
- **Inspected Files:** `src/agents/run.py`, `src/agents/run_internal/tool_execution.py`, `src/agents/tool.py`
- **Reproduction Script:** `test_handoff_guardrail_repro.py`
- **Evidence Log:** `evidence/reproduction.log`

## Verified Findings

1. **Destination `input_guardrails` silently skipped after `NextStepHandoff`** (`src/agents/run.py:1047-1051`, `1530-1542`, `1763-1827`, `2373`):
   - On turn 0 (`current_turn == 0`), `_run_impl` binds `all_input_guardrails` to `starting_agent.input_guardrails` (plus `run_config.input_guardrails`).
   - When `starting_agent` delegates via `handoff(destination_agent)`, `current_agent` updates to `NextStepHandoff.new_agent`, but `current_agent.input_guardrails` are never evaluated on post-handoff turns.
   - **Control:** Invoking `Runner.run(PrivilegedOps, ...)` directly raises `InputGuardrailTripwireTriggered` (`guard_calls == ["PrivilegedOps"]`, `executed == []`).
   - **Bypass:** Invoking `Runner.run(TriageAgent, ...)` followed by `transfer_to_privileged_ops` completes `wire_funds` with `guard_calls == []`.
2. **Built-in & hosted tool classes omit `tool_input_guardrails` / `tool_output_guardrails`** (`src/agents/run_internal/tool_execution.py:2794-2865`):
   - `LocalShellTool`, `ShellTool`, `ApplyPatchTool`, `HostedMCPTool`, and `ComputerTool` expose zero tool guardrail fields; runtime tool-guardrail dispatch only wraps `FunctionTool` and client `MCPServer` tools.
3. **Side-by-Side ADOM Behavior:**
   - Wrapping privileged tools via `adom.integrations.tool_guard.guarded_function_tool` with `ModelProxyPolicy`, or applying `guard_openai_agent(triage, policy=...)` recursively across an OpenAI Agents SDK handoff tree (`test_05`), enforces action-boundary screening, unknown-tool fail-closed denial, and multi-encoding taint detection (`base64`, `hex`) regardless of handoff path, while allowing approved non-tainted actions.

## How to Run

```bash
python -m unittest -v reproductions/openai-agents-guardrail-reproduction/test_handoff_guardrail_repro.py
```

Expected output (`evidence/reproduction.log`): `Ran 5 tests — OK`.

## Defensive Remediation

- Evaluate `new_agent.input_guardrails` when processing `NextStepHandoff` (or attach invariant capability/action screening directly at tool execution time rather than relying solely on entry-agent guardrails).
- Expose tool-boundary hooks uniformly across hosted and shell tool descriptors, not only local `FunctionTool` instances.
