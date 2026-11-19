"""Remote MCP (streamable HTTP, JSON or SSE replies) reverse proxy backed by ADOM Decider + strict SSRF defense.

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
import ssl
import threading
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from adom.enforcement import action_tiers as tiers
from adom.integrations.mcp_gateway import Decider

# Client headers that must reach a remote MCP server for auth and session continuity,
# keyed lowercase -> the one spelling sent upstream. Accept is not passed through: the proxy
# sets it to what it can parse and screen (JSON and SSE).
_PASSTHROUGH_HEADERS = {
    "authorization": "Authorization",
    "mcp-session-id": "Mcp-Session-Id",
    "mcp-protocol-version": "MCP-Protocol-Version",
}
_MAX_CLIENT_BODY = 4 * 1024 * 1024       # largest JSON-RPC request accepted from the client
_MAX_UPSTREAM_BODY = 16 * 1024 * 1024    # largest upstream reply read (JSON or SSE)

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
    resolver=None,
) -> Tuple[urllib.parse.ParseResult, str]:
    """Validate an upstream MCP HTTP(S) URL once and return ``(parsed, pinned_ip)``.

    Connecting via the returned ``pinned_ip`` prevents DNS-rebinding TOCTOU races between
    validation and TCP connect.
    """
    parsed, ips = validate_upstream_ips(url, allow_loopback=allow_loopback, resolver=resolver)
    return parsed, ips[0]


def validate_upstream_ips(
    url: str,
    *,
    allow_loopback: bool = False,
    resolver=None,
) -> Tuple[urllib.parse.ParseResult, List[str]]:
    """Resolve once and return ``(parsed, ips)``: every address the name resolved to, in
    resolver order, each validated. Any blocked answer refuses the whole URL. The proxy dials
    only these addresses (falling back in order, so a dual-stack host with an unreachable IPv6
    route still works) and never resolves again, so DNS rebinding cannot swap one in."""
    resolver = resolver or socket.getaddrinfo
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
    return parsed, ips


def _jsonrpc_error(mid: Any, code: int, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": mid, "error": err}


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a pinned IP but presents ``server_hostname`` for SNI/certs.

    Dialing ``HTTPSConnection(pinned_ip)`` without SNI makes certificate hostname checks
    fail against every real HTTPS MCP server. Keep the pin for DNS-rebinding defense and
    wrap the socket with the original hostname.
    """

    def __init__(self, pinned_ip: str, *, server_hostname: str, port: int, timeout: float):
        ctx = ssl.create_default_context()
        super().__init__(pinned_ip, port=port, timeout=timeout, context=ctx)
        self._adom_server_hostname = server_hostname

    def connect(self) -> None:  # noqa: D401
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if getattr(self, "_tunnel_host", None):
            self.sock = sock
            self._tunnel()
            sock = self.sock
        self.sock = self._context.wrap_socket(sock, server_hostname=self._adom_server_hostname)


class UpstreamReply:
    """One upstream HTTP exchange: status, the session id the server assigned (if any), and
    every JSON-RPC message it returned (a JSON body or the data of each SSE event)."""

    __slots__ = ("status", "session_id", "messages")

    def __init__(self, status: int, session_id: Optional[str], messages: List[Dict[str, Any]]):
        self.status = status
        self.session_id = session_id
        self.messages = messages


def _canonical_passthrough(client_headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Client headers forwarded upstream, under one canonical spelling each (no duplicates)."""
    out: Dict[str, str] = {}
    for key, value in (client_headers or {}).items():
        canon = _PASSTHROUGH_HEADERS.get(str(key).lower())
        if canon and isinstance(value, str) and value and "\r" not in value and "\n" not in value:
            out[canon] = value
    return out


def _messages_from_json(obj: Any) -> List[Dict[str, Any]]:
    if isinstance(obj, dict):
        return [obj]
    if isinstance(obj, list) and all(isinstance(m, dict) for m in obj):
        return list(obj)
    raise RuntimeError("upstream JSON is not a JSON-RPC message or batch")


def parse_sse_messages(raw: bytes) -> List[Dict[str, Any]]:
    """JSON-RPC messages carried in an SSE body (MCP streamable HTTP). Each event's `data:`
    lines are joined with newlines; events without data (comments, keep-alives) are skipped.
    A data payload that is not JSON-RPC fails the whole response closed."""
    text = raw.decode("utf-8")
    messages: List[Dict[str, Any]] = []
    data_lines: List[str] = []

    def _flush() -> None:
        if data_lines:
            payload = "\n".join(data_lines)
            data_lines.clear()
            try:
                obj = json.loads(payload)
            except ValueError as exc:
                raise RuntimeError(f"upstream SSE event is not JSON: {exc}") from exc
            messages.extend(_messages_from_json(obj))

    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line == "":
            _flush()
        elif line.startswith(":"):
            continue
        elif line.startswith("data:"):
            data_lines.append(line[5:][1:] if line[5:].startswith(" ") else line[5:])
        # `event:`, `id:` and `retry:` fields carry no JSON-RPC content
    _flush()
    return messages


class _PinnedUpstreamClient:
    """Dials strictly the DNS-pinned IP returned by ``validate_upstream_url``."""

    def __init__(self, upstream_url: str, *, allow_loopback: bool = False, timeout: float = 10.0,
                 resolver=None):
        self.upstream_url = upstream_url
        self.allow_loopback = allow_loopback
        self.timeout = timeout
        self.parsed, self.pinned_ips = validate_upstream_ips(
            upstream_url, allow_loopback=allow_loopback, resolver=resolver)
        self.pinned_ip = self.pinned_ips[0]

    def _connect(self) -> Tuple[http.client.HTTPConnection, str, str]:
        port = self.parsed.port or (443 if self.parsed.scheme == "https" else 80)
        path = self.parsed.path or "/"
        if self.parsed.query:
            path = f"{path}?{self.parsed.query}"
        hostname = self.parsed.hostname or ""
        host_header = hostname if port in (80, 443) else f"{hostname}:{port}"
        last_exc: Optional[BaseException] = None
        for ip in self.pinned_ips:                 # only addresses validated at startup
            if self.parsed.scheme == "https":
                conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
                    ip, server_hostname=hostname, port=port, timeout=self.timeout)
            else:
                conn = http.client.HTTPConnection(ip, port=port, timeout=self.timeout)
            try:
                conn.connect()
            except ssl.SSLError:
                conn.close()
                raise                              # a certificate problem is not a routing one
            except OSError as exc:
                conn.close()
                last_exc = exc
                continue
            self.pinned_ip = ip                    # remember the address that worked
            return conn, path, host_header
        raise RuntimeError(f"no validated upstream address reachable: {last_exc}")

    def post(self, body: bytes, extra_headers: Optional[Dict[str, str]] = None) -> UpstreamReply:
        """POST one JSON-RPC message or batch. Raises (so the caller fails closed) on transport
        errors, HTTP >= 400, oversized bodies, and content it cannot screen."""
        conn, path, host_header = self._connect()
        try:
            headers = {
                "Host": host_header,
                "Content-Type": "application/json",
                # MCP streamable HTTP: clients MUST accept both. Both are parsed and screened.
                "Accept": "application/json, text/event-stream",
                "Content-Length": str(len(body)),
            }
            headers.update(_canonical_passthrough(extra_headers))
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(_MAX_UPSTREAM_BODY + 1)
            if len(raw) > _MAX_UPSTREAM_BODY:
                raise RuntimeError("upstream response exceeds size limit")
            if resp.status >= 400:
                raise RuntimeError(f"upstream returned HTTP {resp.status}")
            session_id = resp.getheader("Mcp-Session-Id")
            if not raw.strip():
                # 202 Accepted (notifications, client responses) carries no body by spec.
                return UpstreamReply(resp.status, session_id, [])
            ctype = (resp.getheader("Content-Type") or "").lower()
            if "text/event-stream" in ctype:
                return UpstreamReply(resp.status, session_id, parse_sse_messages(raw))
            if "json" in ctype or not ctype:
                return UpstreamReply(resp.status, session_id,
                                     _messages_from_json(json.loads(raw.decode("utf-8"))))
            raise RuntimeError(f"upstream returned unsupported content type {ctype!r}")
        finally:
            conn.close()

    def post_json(self, body: bytes, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Backward-compatible helper: the single JSON-RPC message the server returned."""
        reply = self.post(body, extra_headers)
        if len(reply.messages) != 1:
            raise RuntimeError("upstream did not return exactly one JSON-RPC message")
        return reply.messages[0]

    def delete(self, extra_headers: Optional[Dict[str, str]] = None) -> int:
        """Forward an MCP session termination (HTTP DELETE). Returns the upstream status."""
        conn, path, host_header = self._connect()
        try:
            headers = {"Host": host_header, "Content-Length": "0"}
            headers.update(_canonical_passthrough(extra_headers))
            conn.request("DELETE", path, headers=headers)
            resp = conn.getresponse()
            resp.read(_MAX_UPSTREAM_BODY)
            return resp.status
        finally:
            conn.close()


class McpHttpProxyServer:
    """Local HTTP JSON-RPC MCP proxy enforcing ADOM Decider policies fail-closed.

    Speaks MCP streamable HTTP to the upstream: forwards Authorization / Mcp-Session-Id /
    Mcp-Protocol-Version, returns the server-assigned Mcp-Session-Id to the client, passes
    202 replies to notifications through, and screens responses whether the server answers
    with JSON or with an SSE stream. Responses always reach the client as JSON. GET (a
    standalone server-to-client SSE stream) is answered 405, which the spec allows; servers
    that need to send requests to the client mid-call (sampling, elicitation) are refused,
    as the stdio gateway refuses them in enforce mode.
    """

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
            protocol_version = "HTTP/1.1"

            def _reply(self, status: int, body_obj: Any, session_id: Optional[str] = None,
                       extra: Optional[Dict[str, str]] = None) -> None:
                encoded = b"" if body_obj is None else json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                if body_obj is not None:
                    self.send_header("Content-Type", "application/json")
                if session_id and "\r" not in session_id and "\n" not in session_id:
                    self.send_header("Mcp-Session-Id", session_id)
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                if encoded:
                    self.wfile.write(encoded)

            def _passthrough(self) -> Dict[str, str]:
                return {k: v for k, v in self.headers.items() if k.lower() in _PASSTHROUGH_HEADERS}

            def do_POST(self) -> None:  # noqa: N802
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = -1
                if length < 0 or length > _MAX_CLIENT_BODY:
                    self.close_connection = True
                    self._reply(413 if length > 0 else 400,
                                _jsonrpc_error(None, -32600, "ADOM refused request body size"))
                    return
                raw = self.rfile.read(length) if length > 0 else b""
                status, response_obj, session_id = proxy._handle_payload(
                    raw, client_headers=self._passthrough())
                self._reply(status, response_obj, session_id)

            def do_GET(self) -> None:  # noqa: N802
                # No standalone server-to-client SSE stream through this proxy (spec: 405).
                self._reply(405, None, extra={"Allow": "POST, DELETE"})

            def do_DELETE(self) -> None:  # noqa: N802
                try:
                    status = proxy.upstream.delete(self._passthrough())
                except Exception as exc:
                    self._reply(502, _jsonrpc_error(None, -32002, f"ADOM upstream fail-closed: {exc}"))
                    return
                self._reply(status, None)

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

    def _handle_payload(
        self,
        raw: bytes,
        client_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Any, Optional[str]]:
        """Returns (HTTP status, JSON body or None for an empty 202, upstream session id)."""
        try:
            msg = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return 400, _jsonrpc_error(None, -32700, f"Invalid JSON: {type(exc).__name__}"), None
        if isinstance(msg, list):
            if not msg:
                return 400, _jsonrpc_error(None, -32600, "Empty JSON-RPC batch"), None
            results = []
            status = 200
            session_id: Optional[str] = None
            for item in msg:
                st, res, sid = self._handle_one(item, client_headers=client_headers)
                session_id = sid or session_id
                if st >= 400:
                    status = st
                if res is not None:
                    results.append(res)
            if not results:
                return (202 if status < 400 else status), None, session_id
            return status, results, session_id
        if not isinstance(msg, dict):
            return 400, _jsonrpc_error(None, -32600, "JSON-RPC payload must be an object or array"), None
        return self._handle_one(msg, client_headers=client_headers)

    @staticmethod
    def _screen_auxiliary(method: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        """Mirror stdio gateway credential screens for resources/read and prompts/get."""
        if method == "resources/read":
            uri = params.get("uri")
            if not isinstance(uri, str) or not uri.strip():
                return False, "resources/read without a valid URI"
            target = uri[7:] if uri.lower().startswith("file://") else uri
            cred = tiers.credential_label(target)
            if cred:
                return False, f"credential containment: resources/read blocked ({cred})"
            if tiers._DOTENV_RX.search(target.lower()) and not tiers._DOTENV_SAFE_RX.search(target.lower()):
                return False, "credential containment: resources/read blocked (.env)"
            secs = tiers.secret_labels([uri])
            if secs:
                return False, f"resources/read carries a credential-shaped value ({', '.join(secs)})"
            return True, ""
        if method == "prompts/get":
            pargs = params.get("arguments") or {}
            secs = tiers.secret_labels(tiers.strings(pargs))
            if secs:
                return False, f"prompts/get carries a credential-shaped value ({', '.join(secs)})"
            for path in tiers.paths_in(pargs, everywhere=True):
                cred = tiers.credential_label(path)
                if cred:
                    return False, f"credential containment: prompts/get blocked ({cred})"
            return True, ""
        return True, ""

    def _observe(self, method: str, params: Dict[str, Any], result: Dict[str, Any]) -> None:
        """Feed what the agent is about to read into taint state, as the stdio gateway does.
        If that fails, later outbound decisions would be blind to it: close the session."""
        try:
            if method == "tools/list":
                self.decider.learn_hints(result.get("tools"))
            elif method == "tools/call":
                self.decider.observe(str(params.get("name") or ""), result)
            elif method == "resources/read":
                self.decider.observe("resources/read:" + str(params.get("uri") or "")[:300], result)
            elif method == "prompts/get":
                self.decider.observe("prompts/get:" + str(params.get("name") or "")[:300], result)
        except Exception:
            self.decider.poisoned = ("ADOM could not inspect an earlier result, so it cannot rule "
                                     "out that this call carries it; session closed")

    def _handle_one(
        self,
        msg: Any,
        client_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, Optional[Dict[str, Any]], Optional[str]]:
        if not isinstance(msg, dict):
            return 400, _jsonrpc_error(None, -32600, "Invalid Request"), None
        mid = msg.get("id")
        is_request = "method" in msg and mid is not None
        method = str(msg.get("method") or "")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

        if method == "tools/call":
            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                return 403, _jsonrpc_error(mid, -32602, "ADOM blocked malformed tools/call without tool name"), None
            args = params.get("arguments", {})
            rec = self.decider.decide(tool_name, args)
            if rec["verdict"] != "allow" and self.mode == "enforce":
                return 403, _jsonrpc_error(
                    mid,
                    -32001,
                    f"ADOM blocked MCP tool '{tool_name}': {rec['reason']}",
                    data={"signals": rec["signals"]},
                ), None
        elif method in ("resources/read", "prompts/get"):
            ok, why = self._screen_auxiliary(method, params)
            if not ok and self.mode == "enforce":
                return 403, _jsonrpc_error(mid, -32001, f"ADOM blocked {method}: {why}"), None

        try:
            reply = self.upstream.post(json.dumps(msg).encode("utf-8"), extra_headers=client_headers)
        except Exception as exc:
            # Fail closed on upstream HTTP >= 400, timeout, transport failure, unparseable body
            return 502, _jsonrpc_error(mid, -32002, f"ADOM upstream fail-closed: {exc}"), None

        if not is_request:
            # Notification or client response: the server acknowledges with 202 and no body.
            return 202, None, reply.session_id

        response: Optional[Dict[str, Any]] = None
        server_requests: List[str] = []
        for m in reply.messages:
            if "method" in m:
                if "id" in m:
                    server_requests.append(str(m.get("method")))
                continue                    # server notifications (progress, logging) dropped
            if m.get("id") == mid and ("result" in m or "error" in m):
                response = m
        if response is None:
            why = "no JSON-RPC response for this request"
            if server_requests:
                why = ("server sent request(s) this HTTP proxy cannot relay ("
                       + ", ".join(sorted(set(server_requests)))[:200]
                       + "); use the stdio gateway for servers that need sampling or elicitation")
            return 502, _jsonrpc_error(mid, -32002, f"ADOM upstream fail-closed: {why}"), reply.session_id

        if isinstance(response.get("result"), dict):
            self._observe(method, params, response["result"])
        return 200, response, reply.session_id
