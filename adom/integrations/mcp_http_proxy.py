"""Remote HTTP/SSE JSON-RPC MCP Reverse Proxy backed by ADOM Decider + Strict SSRF Defense.

Fixes both architectural gaps identified in competing OSS proxies/scanners:
  1. Argument-level & cross-tool taint inspection (unlike OpenShell, which inspects
     only ``tools/call`` ``params.name`` and ignores ``params.arguments``).
  2. Fail-closed HTTP relay + strict SSRF IP-pinning blocking loopback, RFC1918,
     CGNAT, ULA, link-local, metadata endpoints, and DNS-rebinding TOCTOU windows
     (unlike snyk/agent-scan, which fails open on 4xx/5xx and allows RFC1918/loopback).
"""

from __future__ import annotations

import http.client
import http.server
import ipaddress
import json
import socket
import threading
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adom.integrations.mcp_gateway import Decider

_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
_ALIBABA_META = ipaddress.ip_network("100.100.100.200/32")
_AWS_V6_META = ipaddress.ip_network("fd00:ec2::254/128")


class UnsafeUpstreamUrl(ValueError):
    """Raised when an upstream MCP URL fails scheme, SSRF IP-range, or DNS checks."""


def _is_blocked_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_loopback: bool) -> Optional[str]:
    if ip_obj.is_loopback:
        return None if allow_loopback else f"loopback address {ip_obj} is blocked"
    if ip_obj.is_link_local:
        return f"link-local / cloud metadata address {ip_obj} is blocked"
    if ip_obj.is_private:
        return f"private/RFC1918/ULA address {ip_obj} is blocked"
    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return f"reserved/multicast/unspecified address {ip_obj} is blocked"
    if isinstance(ip_obj, ipaddress.IPv4Address) and (ip_obj in _CGNAT_NET or ip_obj in _ALIBABA_META):
        return f"CGNAT/metadata address {ip_obj} is blocked"
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in _AWS_V6_META:
        return f"IPv6 metadata address {ip_obj} is blocked"
    if not ip_obj.is_global:
        return f"non-global address {ip_obj} is blocked"
    return None


def validate_upstream_url(
    url: str,
    *,
    allow_loopback: bool = False,
    resolver=socket.getaddrinfo,
) -> Tuple[urllib.parse.ParseResult, str]:
    """Validate an upstream MCP HTTP(S) URL once and return ``(parsed, pinned_ip)``.

    Connecting via the returned ``pinned_ip`` prevents DNS-rebinding TOCTOU races between
    validation and TCP connect.
    """
    parsed = urllib.parse.urlparse(str(url or "").strip())
    if parsed.scheme not in ("http", "https"):
        raise UnsafeUpstreamUrl(f"unsupported scheme {parsed.scheme!r}; only http/https allowed")
    host = parsed.hostname
    if not host:
        raise UnsafeUpstreamUrl("upstream URL has no hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        infos = resolver(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeUpstreamUrl(f"DNS resolution failed for {host!r}: {exc}") from exc

    ips: List[str] = []
    for info in infos:
        raw_ip = str(info[4][0]).split("%", 1)[0]
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise UnsafeUpstreamUrl(f"invalid resolved IP {raw_ip!r}: {exc}") from exc
        reason = _is_blocked_ip(ip_obj, allow_loopback=allow_loopback)
        if reason:
            raise UnsafeUpstreamUrl(f"SSRF blocked for {host!r}: {reason}")
        if raw_ip not in ips:
            ips.append(raw_ip)

    if not ips:
        raise UnsafeUpstreamUrl(f"no usable IP addresses resolved for {host!r}")
    return parsed, ips[0]


def _jsonrpc_error(mid: Any, code: int, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": mid, "error": err}


class _PinnedUpstreamClient:
    """Dials strictly the DNS-pinned IP returned by ``validate_upstream_url``."""

    def __init__(self, upstream_url: str, *, allow_loopback: bool = False, timeout: float = 10.0):
        self.upstream_url = upstream_url
        self.allow_loopback = allow_loopback
        self.timeout = timeout
        self.parsed, self.pinned_ip = validate_upstream_url(upstream_url, allow_loopback=allow_loopback)

    def post_json(self, body: bytes) -> Dict[str, Any]:
        port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        path = self.parsed.path or "/"
        if self.parsed.query:
            path = f"{path}?{self.parsed.query}"
        conn_cls = http.client.HTTPSConnection if self.parsed.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(self.pinned_ip, port=port, timeout=self.timeout)
        try:
            headers = {
                "Host": self.parsed.netloc,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Content-Length": str(len(body)),
            }
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            if resp.status >= 400:
                raise RuntimeError(f"upstream returned HTTP {resp.status}")
            parsed = json.loads(raw.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise RuntimeError("upstream response is not a JSON object")
            return parsed
        finally:
            conn.close()


class McpHttpProxyServer:
    """Local HTTP JSON-RPC MCP proxy enforcing ADOM Decider policies fail-closed."""

    def __init__(
        self,
        upstream_url: str,
        server_name: str,
        *,
        registry_path: Optional[Path] = None,
        client_prompts_confirmed: bool = False,
        mode: str = "enforce",
        allow_loopback: bool = False,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        timeout: float = 10.0,
    ):
        self.mode = mode
        self.decider = Decider(server_name, registry_path, client_prompts_confirmed)
        self.upstream = _PinnedUpstreamClient(upstream_url, allow_loopback=allow_loopback, timeout=timeout)
        proxy = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length > 0 else b""
                status, response_obj = proxy._handle_payload(raw)
                encoded = json.dumps(response_obj, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, format: str, *args: object) -> None:  # noqa: A003
                return

        self._httpd = http.server.ThreadingHTTPServer((bind_host, bind_port), _Handler)
        self.port = self._httpd.server_address[1]
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/mcp"

    def start(self) -> None:
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _handle_payload(self, raw: bytes) -> Tuple[int, Any]:
        try:
            msg = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return 400, _jsonrpc_error(None, -32700, f"Invalid JSON: {type(exc).__name__}")
        if isinstance(msg, list):
            results = []
            status = 200
            for item in msg:
                st, res = self._handle_one(item)
                if st != 200:
                    status = st
                results.append(res)
            return status, results
        if not isinstance(msg, dict):
            return 400, _jsonrpc_error(None, -32600, "JSON-RPC payload must be an object or array")
        return self._handle_one(msg)

    def _handle_one(self, msg: Any) -> Tuple[int, Dict[str, Any]]:
        if not isinstance(msg, dict):
            return 400, _jsonrpc_error(None, -32600, "Invalid Request")
        mid = msg.get("id")
        method = str(msg.get("method") or "")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

        if method == "tools/call":
            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                return 403, _jsonrpc_error(mid, -32602, "ADOM blocked malformed tools/call without tool name")
            args = params.get("arguments", {})
            rec = self.decider.decide(tool_name, args)
            if rec["verdict"] != "allow" and self.mode == "enforce":
                return 403, _jsonrpc_error(
                    mid,
                    -32001,
                    f"ADOM blocked MCP tool '{tool_name}': {rec['reason']}",
                    data={"signals": rec["signals"]},
                )

        try:
            upstream_resp = self.upstream.post_json(json.dumps(msg).encode("utf-8"))
        except Exception as exc:
            # Fail closed on upstream HTTP >= 400, timeout, or transport failure
            return 502, _jsonrpc_error(mid, -32002, f"ADOM upstream fail-closed: {exc}")

        if method == "tools/list" and isinstance(upstream_resp.get("result"), dict):
            self.decider.learn_hints(upstream_resp["result"].get("tools"))
        elif method == "tools/call" and isinstance(upstream_resp.get("result"), dict):
            self.decider.observe(str(params.get("name") or ""), upstream_resp["result"])
        return 200, upstream_resp
