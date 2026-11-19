#!/usr/bin/env python3
"""Records exactly what Kong sends to the guardrail service, then forwards it to ADOM.

Sits between Kong's ai-custom-guardrail plugin and `adom kong-guard`, so the smoke test can
check what Kong really renders (which fields arrive, whether any "$(...)" stays unrendered,
which headers carry identity) instead of assuming it.

usage: capture_proxy.py LISTEN_PORT ADOM_PORT WORK_DIR
"""
import http.client
import http.server
import json
import os
import sys
from pathlib import Path

LISTEN, ADOM, WORK = int(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
LOG = WORK / "guardrail_requests.jsonl"


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _forward(self, method):
        n = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = {"_unparseable": raw[:2000].decode("utf-8", "replace")}
        fwd_headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "content-length", "connection")}
        try:
            c = http.client.HTTPConnection("127.0.0.1", ADOM, timeout=10)
            c.request(method, self.path, body=raw or None, headers=fwd_headers)
            r = c.getresponse()
            out, status = r.read(), r.status
        except Exception as exc:                       # ADOM down: say so, block
            out = json.dumps({"block": True, "block_message": f"capture proxy: {exc}"}).encode()
            status = 502
        try:
            resp = json.loads(out)
        except ValueError:
            resp = out[:2000].decode("utf-8", "replace")
        with LOG.open("a") as f:
            f.write(json.dumps({"method": method, "path": self.path,
                                "headers": dict(self.headers.items()),
                                "body": parsed, "adom_status": status, "adom_response": resp}) + "\n")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_POST(self):
        self._forward("POST")

    def do_GET(self):
        self._forward("GET")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer((os.environ.get("BIND_HOST", "127.0.0.1"), LISTEN), H).serve_forever()
