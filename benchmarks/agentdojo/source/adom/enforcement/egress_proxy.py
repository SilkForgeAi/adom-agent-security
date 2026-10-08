"""
ADOM egress proxy — the universal network chokepoint.

Point any agent's traffic at this proxy (HTTP_PROXY / HTTPS_PROXY) and EVERY
outbound request must pass ADOM's egress policy before it leaves the machine —
regardless of which model is driving the agent (OpenAI, Anthropic, local, anything).

This is the model-agnostic hardening of the network-enforcement layer:
  • plain HTTP   -> full inspection of host + path + body (secret/taint/exfil scan)
  • HTTPS CONNECT -> host allow/deny enforced at tunnel-open (body is encrypted, so
                    an exfil to an un-allowlisted host is refused before the tunnel forms)

On a block it can call `on_block(host, port, reason, signals)` so the containment
engine / flight recorder can seal the attempt. Pure stdlib.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# generic secret shapes to catch even without a known taint value
_SECRET_RX = [
    (re.compile(r"sk-live-[A-Za-z0-9]+"), "stripe_live_key"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "api_key"),
    (re.compile(r"AKIA[0-9A-Z]{12,}"), "aws_access_key"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private_key"),
    (re.compile(r"(?i)\b(password|passwd|db_pass|secret)\s*[=:]\s*\S+"), "credential_kv"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]+"), "slack_token"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "github_token"),
]


def host_of(dest: str) -> str:
    """CANONICAL host extraction. Strips scheme, path, query, port and — critically —
    userinfo (the real host is AFTER the last '@', so 'corp.com@evil.io' -> 'evil.io').

    This is the single implementation used by BOTH enforcement planes. Duplicated host
    parsing is how a fix lands on one plane and not the other; do not re-implement it.
    """
    d = (dest or "").strip().split("://", 1)[-1]
    d = d.split("/", 1)[0].split("?", 1)[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    if d.startswith("["):                      # bracketed IPv6 literal
        return d[:d.find("]") + 1].lower() if "]" in d else d.lower()
    d = d.split(":", 1)[0]
    return d.lower().strip().strip(".")


def host_matches(host: str, patterns, allow_subdomains: bool = True) -> bool:
    """CANONICAL allowlist test: EXACT host, or a real subdomain of an allowed host.

    NEVER a substring test. Substring matching lets 'corp.com.evil.io' and 'notcorp.com'
    inherit permission from an allowlisted 'corp.com' — a trivially registrable bypass of
    the only control that applies to HTTPS (a CONNECT tunnel has no body to scan).

    allow_subdomains=False gives EXACT-only matching, required wherever a match grants the
    right to reach an internal address: letting a subdomain inherit that is an SSRF hole.
    """
    if not patterns:
        return False
    h = host_of(host)
    if not h:
        return False
    for p in patterns:
        a = str(p).lower().strip().rstrip(".").lstrip(".")
        if not a:
            continue
        if h == a or (allow_subdomains and h.endswith("." + a)):
            return True
    return False


class EgressPolicy:
    """Decides whether a single outbound request may leave."""

    def __init__(self, allow_hosts: Optional[List[str]] = None,
                 deny_hosts: Optional[List[str]] = None,
                 taint_values: Optional[List[str]] = None,
                 block_generic_secrets: bool = True):
        self.allow_hosts = [h.lower() for h in allow_hosts] if allow_hosts is not None else None
        self.deny_hosts = [h.lower() for h in (deny_hosts or [])]
        self.taint_values = [v for v in (taint_values or []) if v]
        self.block_generic_secrets = block_generic_secrets

    def add_taint(self, value: str):
        if value and value not in self.taint_values:
            self.taint_values.append(value)

    def explicitly_allows(self, host: str) -> bool:
        """True only when the operator named THIS EXACT host in the allowlist.

        Such a host may resolve to an internal address (internal APIs and loopback sinks are
        legitimate targets); rebinding is still defeated because the connection is PINNED to the
        single resolved address. The match must be EXACT — allowing 'partner.example' must not
        let an attacker's 'evil.partner.example' inherit permission to resolve to a private
        address, which is a subdomain-based SSRF hole."""
        return host_matches(host, self.allow_hosts, allow_subdomains=False)

    def decide(self, host: str, port: int, method: str, path: str,
               body: bytes, headers: Optional[Dict[str, str]] = None
               ) -> Tuple[bool, str, List[str]]:
        """Screen one outbound request.

        `headers` is optional for backwards compatibility, but callers should pass it. The
        scan previously covered only path+body, so a secret placed in a request HEADER
        (X-Data, Cookie, a crafted Authorization) was forwarded completely unscanned — a
        one-line exfil that needed no encoding at all. Headers are attacker-controllable on
        any outbound call, so they belong in the same blob as the body.
        """
        h = host_of(host)
        # Deny stays deliberately broad (substring): over-blocking is fail-closed.
        if self.deny_hosts and any(d in h for d in self.deny_hosts):
            return False, f"egress:denied_host:{h}", ["egress:denied_host"]
        # ALLOW uses the canonical exact-or-subdomain test — never a substring test.
        if self.allow_hosts is not None and not host_matches(h, self.allow_hosts):
            return False, f"egress:host_not_allowlisted:{h}", ["egress:not_allowlisted"]

        hdr_blob = ""
        if headers:
            # Skip hop-by-hop noise; keep everything an attacker could stuff data into.
            _skip = ("proxy-connection", "connection", "keep-alive", "content-length",
                     "accept-encoding", "user-agent", "accept")
            hdr_blob = " ".join(f"{k}: {v}" for k, v in headers.items()
                                if str(k).lower() not in _skip)
        blob = ((path or "") + " " + hdr_blob + " "
                + (body.decode("utf-8", "ignore") if body else ""))
        for val in self.taint_values:
            if val in blob:
                return False, "egress:secret_in_outbound:critical", ["exfil:secret_in_outbound:critical"]
        if self.block_generic_secrets:
            for rx, label in _SECRET_RX:
                if rx.search(blob):
                    return False, f"egress:secret_pattern:{label}", [f"exfil:{label}"]
        return True, "ok", []


def _is_internal_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                or a.is_unspecified or a.is_multicast)


def resolve_and_pin(host: str, port: int,
                    permit_internal: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """Resolve ONCE, validate every answer, and return a single pinned IP to connect to.

    DNS REBINDING DEFENSE. Checking a hostname and then calling create_connection(host, ...)
    resolves DNS a second time — so an attacker who controls the zone can answer with a public
    IP for the policy check and an internal IP microseconds later for the actual connection.
    Pinning removes the second lookup: the address the policy approved is the address we dial.
    Every resolved answer must be public; if ANY answer is internal we refuse, because a
    round-robin record must not be usable to smuggle in a private target.

    Returns (ip, None) on success or (None, reason) on refusal (fail-closed).
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except Exception as e:
        return None, f"dns_resolution_failed:{e}"
    if not infos:
        return None, "dns_no_answer"
    ips = []
    for _fam, _typ, _pr, _canon, sa in infos:
        if sa and isinstance(sa[0], str):
            ips.append(sa[0])
    if not ips:
        return None, "dns_no_address"
    if not permit_internal:
        for ip in ips:
            if _is_internal_ip(ip):
                return None, f"internal_address_in_dns_answer:{ip}"
    return ips[0], None


_MAX_BODY = 64 * 1024 * 1024      # bound memory per request (DoS)


def _read_request_body(rfile, headers) -> Tuple[bytes, str]:
    """Read a request body under either framing. Returns (body, error).

    Content-Length alone is not enough: `Transfer-Encoding: chunked` carries a body with no
    Content-Length, and the previous code then read nothing and scanned nothing. An inspector
    that can be skipped by picking a different framing is not an inspector.
    """
    te = str(headers.get("Transfer-Encoding", "") or "").lower()
    if "chunked" in te:
        out = bytearray()
        while True:
            line = rfile.readline(1024)
            if not line:
                return bytes(out), "truncated_chunked_stream"
            try:
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
            except ValueError:
                return bytes(out), "bad_chunk_size"
            if size == 0:
                while True:                      # consume trailers
                    t = rfile.readline(1024)
                    if not t or t in (b"\r\n", b"\n"):
                        break
                return bytes(out), ""
            if len(out) + size > _MAX_BODY:
                return bytes(out), "body_too_large"
            chunk = rfile.read(size)
            out += chunk
            rfile.read(2)                        # trailing CRLF
        # unreachable
    try:
        n = int(headers.get("Content-Length", 0) or 0)
    except ValueError:
        return b"", "bad_content_length"
    if n < 0 or n > _MAX_BODY:
        return b"", "body_too_large"
    return (rfile.read(n) if n else b""), ""


def make_handler(policy: EgressPolicy,
                 on_block: Optional[Callable[[str, int, str, List[str]], None]] = None):

    class _H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # quiet
            pass

        def _blocked(self, host, port, reason, signals):
            if on_block:
                try: on_block(host, port, reason, signals)
                except Exception: pass
            msg = ("ADOM blocked this egress: " + reason).encode()
            self.send_response(403)
            self.send_header("X-ADOM-Blocked", reason)
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

        # ---- HTTPS: enforce host at tunnel open (body is encrypted) ----
        def do_CONNECT(self):
            host, _, port = self.path.partition(":")
            port = int(port or 443)
            ok, reason, sigs = policy.decide(host, port, "CONNECT", "", b"")
            if not ok:
                return self._blocked(host, port, reason, sigs)
            # resolve-then-pin: no second DNS lookup between the check and the connect
            ip, why = resolve_and_pin(host, port, policy.explicitly_allows(host))
            if ip is None:
                return self._blocked(host, port, f"egress:dns_pin_refused:{why}",
                                     ["egress:dns_rebinding_or_internal_target:high"])
            try:
                upstream = socket.create_connection((ip, port), timeout=10)
            except Exception:
                self.send_response(502); self.end_headers(); return
            self.send_response(200, "Connection Established"); self.end_headers()
            self._tunnel(self.connection, upstream)

        def _tunnel(self, a, b):
            a.setblocking(False); b.setblocking(False)
            try:
                while True:
                    r, _, x = select.select([a, b], [], [a, b], 30)
                    if x or not r:
                        break
                    for s in r:
                        try: data = s.recv(65536)
                        except Exception: return
                        if not data:
                            return
                        (b if s is a else a).sendall(data)
            finally:
                for s in (a, b):
                    try: s.close()
                    except Exception: pass

        # ---- plain HTTP: full inspection ----
        def _proxy(self):
            u = urlparse(self.path)
            host, port = u.hostname, (u.port or 80)
            path = u.path or "/"
            if u.query:
                path += "?" + u.query
            # Read the body for BOTH framings. Handling only Content-Length meant a request
            # sent with `Transfer-Encoding: chunked` reported length 0, so the body was never
            # read and never scanned — the secret scan was skipped by choosing a framing.
            body, read_err = _read_request_body(self.rfile, self.headers)
            if read_err:
                return self._blocked(host, port, f"egress:malformed_body:{read_err}",
                                     ["egress:unreadable_body:fail_closed"])
            ok, reason, sigs = policy.decide(host, port, self.command, path, body,
                                             dict(self.headers.items()))
            if not ok:
                return self._blocked(host, port, reason, sigs)
            # resolve-then-pin (see resolve_and_pin): connect to the validated IP, but keep the
            # original Host header so virtual hosting still works
            ip, why = resolve_and_pin(host, port, policy.explicitly_allows(host))
            if ip is None:
                return self._blocked(host, port, f"egress:dns_pin_refused:{why}",
                                     ["egress:dns_rebinding_or_internal_target:high"])
            try:
                conn = http.client.HTTPConnection(ip, port, timeout=15)
                hdrs = {k: v for k, v in self.headers.items()
                        if k.lower() not in ("proxy-connection", "connection",
                                             "transfer-encoding", "content-length")}
                hdrs["Host"] = host if port in (80, 443) else f"{host}:{port}"
                conn.request(self.command, path, body=body or None, headers=hdrs)
                resp = conn.getresponse()
                data = resp.read()
            except Exception as e:
                m = f"ADOM egress upstream error: {e}".encode()
                self.send_response(502); self.send_header("Content-Length", str(len(m)))
                self.end_headers(); self.wfile.write(m); return
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() in ("transfer-encoding", "connection", "keep-alive"):
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _proxy

    return _H


def start(policy: EgressPolicy, host: str = "127.0.0.1", port: int = 8888,
          on_block: Optional[Callable] = None) -> ThreadingHTTPServer:
    """Start the proxy in a background thread; returns the server (call .shutdown())."""
    srv = ThreadingHTTPServer((host, port), make_handler(policy, on_block))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    pol = EgressPolicy(taint_values=["hunter2"])
    s = start(pol, port=8888)
    print("ADOM egress proxy on 127.0.0.1:8888 — set HTTP_PROXY=http://127.0.0.1:8888")
    import time
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        s.shutdown()
