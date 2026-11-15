# ADOM MCP gateway (v1, 2026-10-25)

Implementation: `adom/integrations/mcp_gateway.py`. Tests: `adom/integrations/tests/test_mcp_gateway.py`
(18 tests, a real gateway process between the test and a real fake MCP server; what reached the
server is read from the server's own effects file).

## What it is

A stdio MCP server that the client talks to instead of the real one. It starts the real
server as a child process and relays JSON-RPC both ways. Every `tools/call` is decided by
ADOM before the real server sees it. Any MCP client works (Claude Code, Cursor, Claude
Desktop, custom agents) because the gateway is just another MCP server to them.

```json
{
  "mcpServers": {
    "notes": {
      "command": "python3",
      "args": ["-m", "adom.integrations.mcp_gateway", "--name", "notes",
               "--", "npx", "-y", "some-notes-mcp-server"],
      "cwd": "/path/to/adom-agent-security"
    }
  }
}
```

## Decision path for one tools/call

1. Name it `mcp__<name>__<tool>` (the same key the coding-agent hooks and the registry use).
2. `action_tiers.classify`: operator registry `~/.adom/tool_tiers.json`, raised (never
   lowered) by the server's own `tools/list` annotations.
3. Denied outright: unknown tool; a credential path in any argument (any string that is a
   path or `file://` URI, symlinks and hard links resolved); a credential-shaped value in a
   consequential or unknown call's arguments; a session whose earlier result could not be
   inspected.
4. Otherwise ADOM's kernel (`action_kernel.screen_action`) decides, with an exact grant for
   that one tool and the entry's `approved_outbound`. One long-lived kernel policy per granted
   tool keeps session state, and every permitted result is fed back (`note_read`), so a value
   read through one tool is caught if the agent tries to send it through another.
5. Kernel "review required" (an outbound call nothing objected to) blocks, unless the registry
   entry sets `agent_approval: true` AND the operator started the gateway with
   `--client-prompts-confirmed` (a statement that the client shows a person every tool call;
   it is written into every record). Hard kernel signals always block.
6. A denied call never reaches the server. The client receives an MCP tool error
   (`isError: true`) with the reason, so the agent can continue.

## Evidence

- 18/18 tests on the Mac (Python 3.10) and in the cloud (Python 3.13); vermin: Python 3.7+.
- Four mutants of the gateway (never block, no taint learning, ignore hints, honour
  agent_approval without the operator flag) were each killed by the suite.

## Limits

- stdio transport only; Streamable HTTP / SSE are not supported yet.
- It sees only traffic routed through it. A client with another route to the server, or a
  server acting on its own, is outside its view.
- Batched JSON-RPC arrays are split and each element decided; responses come back individually.
- The audit chain is unkeyed: it reveals a middle record edited or removed, not a truncated
  tail or a fully rewritten log. Copy the head hash elsewhere (`python3 -m
  adom.integrations.mcp_gateway verify ~/.adom/mcp/<name>.jsonl` checks a log).
- Taint learning is per gateway process (per server). Two gateways for two servers do not
  share what the agent read.
