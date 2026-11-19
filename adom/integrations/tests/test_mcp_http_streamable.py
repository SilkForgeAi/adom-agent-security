"""MCP streamable-HTTP behavior of `adom mcp-http` (McpHttpProxyServer).

The fake upstream follows the MCP streamable HTTP transport the way the official SDK
server does by default: POSTs must accept both application/json and text/event-stream,
requests are answered over SSE, initialize assigns an Mcp-Session-Id that every later
request must carry, and notifications are acknowledged with 202 and no body.
"""
from __future__ import annotations

import base64
import http.client
import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

from adom.integrations.mcp_http_proxy import McpHttpProxyServer, parse_sse_messages

SECRET = "AKIA" + "5566778899001122"
SESSION = "sess-7f3a"


class _SpecServer(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    log: list = []           # (method, headers-lowercase, body) per request; reset per test

    def _send(self, status: int, body: bytes = b"", ctype: str = "", extra: dict = None) -> None:
        self.send_response(status)
        if ctype:
            self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _sse(self, *messages: dict, extra: dict = None) -> None:
        events = "".join(": keep-alive\n\nevent: message\ndata: " + json.dumps(m) + "\n\n" for m in messages)
        self._send(200, events.encode(), "text/event-stream", extra)

    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length", "0"))
        msg = json.loads(self.rfile.read(n))
        hdrs = {k.lower(): v for k, v in self.headers.items()}
        type(self).log.append(("POST", hdrs, msg))
        accept = hdrs.get("accept", "")
        if "application/json" not in accept or "text/event-stream" not in accept:
            return self._send(406, b'{"error":"Not Acceptable"}', "application/json")
        method, mid = msg.get("method"), msg.get("id")
        if method == "initialize":
            return self._sse({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "spec", "version": "1"}}}, extra={"Mcp-Session-Id": SESSION})
        if hdrs.get("mcp-session-id") != SESSION:
            return self._send(400, b'{"error":"Bad Request: missing session"}', "application/json")
        if mid is None:                                   # notification or client response
            return self._send(202)
        if method == "tools/list":
            return self._sse(
                {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}},
                {"jsonrpc": "2.0", "id": mid, "result": {"tools": [
                    {"name": "read_note"}, {"name": "send_email"}, {"name": "needs_sampling"}]}})
        if method == "resources/read":
            body = json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"contents": [
                {"uri": msg["params"]["uri"], "mimeType": "text/plain", "text": f"aws={SECRET}"}]}})
            return self._send(200, body.encode(), "application/json")
        if method == "tools/call":
            tool = msg["params"]["name"]
            if tool == "read_note":
                return self._sse({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": f"KEY={SECRET}"}]}})
            if tool == "needs_sampling":
                return self._sse({"jsonrpc": "2.0", "id": 900, "method": "sampling/createMessage",
                                  "params": {"messages": []}})
            return self._sse({"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": "sent"}]}})
        return self._sse({"jsonrpc": "2.0", "id": mid, "result": {}})

    def do_DELETE(self) -> None:  # noqa: N802
        type(self).log.append(("DELETE", {k.lower(): v for k, v in self.headers.items()}, None))
        self._send(200 if self.headers.get("Mcp-Session-Id") == SESSION else 404)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


class StreamableHttpProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        _SpecServer.log = []
        self.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SpecServer)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.td = tempfile.TemporaryDirectory()
        reg = Path(self.td.name) / "tool_tiers.json"
        reg.write_text(json.dumps({"version": 1, "tools": {
            "mcp__spec__read_note": {"tier": "observe"},
            "mcp__spec__needs_sampling": {"tier": "observe"},
            "mcp__spec__send_email": {"tier": "consequential", "agent_approval": True,
                                      "approved_outbound": ["corp.com"]},
        }}))
        self.proxy = McpHttpProxyServer(
            f"http://localhost:{self.upstream.server_address[1]}/mcp", "spec",
            registry_path=reg, client_prompts_confirmed=True, allow_loopback=True)
        self.proxy.start()

    def tearDown(self) -> None:
        self.proxy.close()
        self.upstream.shutdown()
        self.upstream.server_close()
        self.td.cleanup()

    # -- helpers
    def _http(self, method: str, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.proxy.port, timeout=10)
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        h.update(headers or {})
        c.request(method, "/mcp", body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        c.close()
        return r.status, {k.lower(): v for k, v in r.getheaders()}, (json.loads(raw) if raw else None)

    def _handshake(self) -> str:
        st, hdrs, body = self._http("POST", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(st, 200)
        self.assertEqual(body["result"]["serverInfo"]["name"], "spec")
        sid = hdrs.get("mcp-session-id")
        self.assertEqual(sid, SESSION, "server-assigned session id must reach the client")
        st, hdrs, body = self._http("POST", {"jsonrpc": "2.0", "method": "notifications/initialized"},
                                    {"Mcp-Session-Id": sid})
        self.assertEqual((st, body), (202, None), "notification ack is 202 with no body")
        return sid

    def _upstream_tool_calls(self):
        return [m["params"]["name"] for verb, _, m in _SpecServer.log
                if verb == "POST" and m.get("method") == "tools/call"]

    # -- tests
    def test_handshake_and_sse_response_is_screened_and_returned_as_json(self) -> None:
        sid = self._handshake()
        st, hdrs, body = self._http("POST", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                                    {"Mcp-Session-Id": sid})
        self.assertEqual(st, 200)
        self.assertTrue(hdrs["content-type"].startswith("application/json"))
        self.assertEqual(body["id"], 2)                      # progress notification dropped
        self.assertEqual([t["name"] for t in body["result"]["tools"]],
                         ["read_note", "send_email", "needs_sampling"])
        # Upstream always got a spec-compliant Accept, exactly once
        for verb, h, _ in _SpecServer.log:
            if verb == "POST":
                self.assertIn("text/event-stream", h["accept"])

    def test_taint_learned_from_sse_tool_result_blocks_exfil(self) -> None:
        sid = self._handshake()
        st, _, body = self._http("POST", {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                          "params": {"name": "read_note", "arguments": {"path": "k"}}},
                                 {"Mcp-Session-Id": sid})
        self.assertEqual(st, 200)
        self.assertIn(SECRET, body["result"]["content"][0]["text"])
        b64 = base64.b64encode(SECRET.encode()).decode()
        st, _, body = self._http("POST", {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                          "params": {"name": "send_email",
                                                     "arguments": {"to": "ops@corp.com", "body": b64}}},
                                 {"Mcp-Session-Id": sid})
        self.assertEqual(st, 403)
        self.assertEqual(self._upstream_tool_calls(), ["read_note"])

    def test_taint_learned_from_resources_read_blocks_exfil(self) -> None:
        sid = self._handshake()
        st, _, _ = self._http("POST", {"jsonrpc": "2.0", "id": 5, "method": "resources/read",
                                       "params": {"uri": "notes://ops"}}, {"Mcp-Session-Id": sid})
        self.assertEqual(st, 200)
        st, _, _ = self._http("POST", {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
                                       "params": {"name": "send_email",
                                                  "arguments": {"to": "ops@corp.com", "body": SECRET[::-1]}}},
                              {"Mcp-Session-Id": sid})
        self.assertEqual(st, 403)
        self.assertEqual(self._upstream_tool_calls(), [])

    def test_server_request_mid_call_fails_closed(self) -> None:
        sid = self._handshake()
        st, _, body = self._http("POST", {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                          "params": {"name": "needs_sampling", "arguments": {}}},
                                 {"Mcp-Session-Id": sid})
        self.assertEqual(st, 502)
        self.assertIn("sampling/createMessage", body["error"]["message"])

    def test_missing_session_still_fails_closed(self) -> None:
        st, _, body = self._http("POST", {"jsonrpc": "2.0", "id": 8, "method": "tools/list"})
        self.assertEqual(st, 502)
        self.assertIn("fail-closed", body["error"]["message"])

    def test_get_is_405_and_delete_is_forwarded(self) -> None:
        sid = self._handshake()
        st, hdrs, body = self._http("GET")
        self.assertEqual((st, body), (405, None))
        self.assertIn("POST", hdrs.get("allow", ""))
        st, _, _ = self._http("DELETE", headers={"Mcp-Session-Id": sid})
        self.assertEqual(st, 200)
        deletes = [h for verb, h, _ in _SpecServer.log if verb == "DELETE"]
        self.assertEqual(deletes[-1].get("mcp-session-id"), SESSION)

    def test_batch_of_notifications_is_202(self) -> None:
        sid = self._handshake()
        st, _, body = self._http("POST", [{"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
                                          {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}}],
                                 {"Mcp-Session-Id": sid})
        self.assertEqual((st, body), (202, None))

    def test_passthrough_headers_are_canonical_and_not_duplicated(self) -> None:
        sid = self._handshake()
        st, _, _ = self._http("POST", {"jsonrpc": "2.0", "id": 9, "method": "ping"},
                              {"mcp-session-id": sid, "authorization": "Bearer t0k",
                               "accept": "application/json"})          # lowercase client spelling
        self.assertEqual(st, 200)
        _, h, _ = _SpecServer.log[-1]
        self.assertEqual(h.get("authorization"), "Bearer t0k")
        self.assertIn("text/event-stream", h["accept"])                 # proxy sets Accept

    def test_oversized_client_body_refused(self) -> None:
        # Refused from the declared length, before the body is read (so send headers only).
        import socket
        with socket.create_connection(("127.0.0.1", self.proxy.port), timeout=10) as s:
            s.sendall(b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                      b"Content-Length: 5242880\r\n\r\n")
            status_line = s.recv(256).split(b"\r\n", 1)[0]
        self.assertIn(b" 413 ", status_line)
        self.assertEqual(_SpecServer.log, [])                # nothing reached upstream


class ParseSseTests(unittest.TestCase):
    def test_events_comments_multiline_and_crlf(self) -> None:
        raw = (": hi\r\nevent: message\r\ndata: {\"jsonrpc\":\"2.0\",\r\ndata: \"id\":1,\"result\":{}}\r\n\r\n"
               "data: [{\"jsonrpc\":\"2.0\",\"method\":\"n\"}]\n\n").encode()
        msgs = parse_sse_messages(raw)
        self.assertEqual([m.get("id", m.get("method")) for m in msgs], [1, "n"])

    def test_non_json_data_fails(self) -> None:
        with self.assertRaises(RuntimeError):
            parse_sse_messages(b"data: not json\n\n")


if __name__ == "__main__":
    unittest.main(verbosity=1)
