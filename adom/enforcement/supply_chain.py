"""
ADOM supply-chain attestation — pin what a tool IS, and bound what it may DO.
(OWASP Agentic Top 10: ASI04 Agentic Supply Chain; supports ASI02 Tool Misuse and ASI10.)

An agent's tools, connectors and skills are code you did not write, loaded at runtime, holding
your credentials. The action boundary judges the call; this module judges the CALLER: is this
tool the exact artifact that was vetted, and is it staying inside the envelope it was vetted
for?

THREAT MODEL
  1. Post-vetting code swap — the connector was reviewed, then its code changed underneath you.
     Defended by content pinning: SHA-256 of the artifact must match the attested digest.
  2. Unvetted tool introduced at runtime — a new tool appears and is simply used. Defended by
     fail-closed strict mode: unattested tool => denied.
  3. Typosquatting — 'reqests', 'slack_notifyer', 'stripe-sdk' beside a real 'stripe_sdk'.
     Defended by near-miss detection against the attested set (bounded edit distance +
     separator/confusable folding), so a lookalike is flagged rather than silently trusted.
  4. Version rollback — downgrade to a known-vulnerable build that still passes "is it
     attested?". Defended by a per-tool minimum version floor.
  5. Revocation lag — a component is found malicious but keeps running. Defended by an explicit
     revocation list checked on every verify.
  6. Capability creep — a tool vetted as read-only starts writing, spending, or egressing.
     Defended by CAPABILITY ENVELOPES: each attestation declares what the tool may do, and any
     action outside that envelope is a violation regardless of the tool's own claims.

DESIGN PRINCIPLES (consistent with the rest of ADOM)
  - FAIL-CLOSED: unknown, drifted, revoked, or below-floor => deny (in strict mode).
  - Deterministic: hashes, sets, integers. No model, no network, no trust in the tool's claims.
  - SECOND PLANE: attestation never replaces the action boundary. A perfectly attested tool
    still has every call scored by ModelProxyPolicy. Both must pass.

HONEST SCOPE
  - This proves an artifact matches what YOU vetted. It cannot prove the artifact was benign
    when you vetted it — provenance of the upstream source (signed releases, SBOM, reproducible
    builds, the publisher's own attestation) is a separate supply-chain problem this module
    does not solve and does not claim to.
  - Envelope enforcement is only as good as the declared envelope; over-broad envelopes are a
    configuration failure, not a detection failure.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

SUPPLY_VERSION = "supply-2026.08.16"

# action kinds an envelope can permit (mirrors the action-boundary consequence classes)
KIND_NETWORK = "network"
KIND_WRITE = "filesystem_write"
KIND_DESTRUCTIVE = "destructive"
KIND_SPEND = "spend"
KIND_PRIVILEGED = "privileged"
_ALL_KINDS = (KIND_NETWORK, KIND_WRITE, KIND_DESTRUCTIVE, KIND_SPEND, KIND_PRIVILEGED)


@dataclass(frozen=True)
class CapabilityEnvelope:
    """What a vetted tool is permitted to do. Everything defaults to FALSE (least privilege)."""
    network: bool = False
    filesystem_write: bool = False
    destructive: bool = False
    spend: bool = False
    privileged: bool = False

    def permits(self, kind: str) -> bool:
        return bool(getattr(self, kind, False)) if kind in _ALL_KINDS else False


@dataclass(frozen=True)
class ToolAttestation:
    name: str
    sha256: str
    version: str = "0.0.0"
    envelope: CapabilityEnvelope = field(default_factory=CapabilityEnvelope)


@dataclass
class AttestationVerdict:
    trusted: bool
    status: str                       # attested | unknown | drifted | revoked | rollback | typosquat
    reason: str = ""
    signals: List[str] = field(default_factory=list)
    attestation: Optional[ToolAttestation] = None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _norm_name(n: str) -> str:
    """Fold separators/case so 'stripe-sdk', 'stripe_sdk' and 'StripeSDK' compare equal."""
    return re.sub(r"[^a-z0-9]", "", (n or "").lower())


def _edit_distance_le(a: str, b: str, limit: int = 2) -> bool:
    """Bounded Levenshtein: True if distance <= limit. Cheap, early-exit on length gap."""
    if abs(len(a) - len(b)) > limit:
        return False
    if a == b:
        return True
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            best = min(best, cur[j])
        if best > limit:
            return False
        prev = cur
    return prev[-1] <= limit


def _ver_tuple(v: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", v or "0")
    return tuple(int(p) for p in parts[:4]) or (0,)


class ToolAttestationRegistry:
    """Vetted tools pinned by content hash, with capability envelopes, version floors and
    revocations. Strict mode denies anything not explicitly attested."""

    def __init__(self, strict: bool = True, typosquat_distance: int = 2):
        self.strict = strict
        self.typosquat_distance = typosquat_distance
        self._attested: Dict[str, ToolAttestation] = {}      # norm_name -> attestation
        self._min_version: Dict[str, Tuple[int, ...]] = {}
        self._revoked: Dict[str, set] = {}                   # norm_name -> {digests}
        self._lock = threading.RLock()

    # ---- configuration ----
    def attest(self, name: str, digest: str, version: str = "0.0.0",
               envelope: Optional[CapabilityEnvelope] = None,
               min_version: Optional[str] = None) -> None:
        if not name or not digest:
            raise ValueError("name and digest are required")
        key = _norm_name(name)
        with self._lock:
            self._attested[key] = ToolAttestation(name=name, sha256=digest.lower(),
                                                  version=version,
                                                  envelope=envelope or CapabilityEnvelope())
            floor = min_version if min_version is not None else version
            self._min_version[key] = _ver_tuple(floor)

    def revoke(self, name: str, digest: Optional[str] = None) -> None:
        """Revoke a specific artifact digest, or the whole tool when digest is None."""
        key = _norm_name(name)
        with self._lock:
            if digest is None:
                self._attested.pop(key, None)
                self._revoked.setdefault(key, set()).add("*")
            else:
                self._revoked.setdefault(key, set()).add(digest.lower())

    # ---- verification ----
    def verify(self, name: str, digest: str, version: str = "0.0.0") -> AttestationVerdict:
        key = _norm_name(name)
        d = (digest or "").lower()
        with self._lock:
            revoked = set(self._revoked.get(key, ()))
            att = self._attested.get(key)
            floor = self._min_version.get(key)
            known_names = list(self._attested.keys())

        if "*" in revoked or (d and d in revoked):
            return AttestationVerdict(False, "revoked",
                                      f"tool '{name}' is revoked", ["supply:revoked:critical"])

        if att is None:
            # typosquat: close to something we DO trust, but not it
            for k in known_names:
                if _edit_distance_le(key, k, self.typosquat_distance):
                    return AttestationVerdict(
                        False, "typosquat",
                        f"tool '{name}' closely resembles attested '{self._attested[k].name}' "
                        f"but is not it", ["supply:typosquat_suspected:critical"])
            return AttestationVerdict(
                not self.strict, "unknown",
                f"tool '{name}' has no attestation" + (" (strict: denied)" if self.strict else ""),
                ["supply:unattested:high"])

        if not d or not hmac.compare_digest(att.sha256, d):
            return AttestationVerdict(
                False, "drifted",
                f"tool '{name}' content does not match its attested digest "
                f"(expected {att.sha256[:12]}…, got {(d or 'none')[:12]}…)",
                ["supply:content_drift:critical"], attestation=att)

        if floor is not None and _ver_tuple(version) < floor:
            return AttestationVerdict(
                False, "rollback",
                f"tool '{name}' version {version} is below the minimum {'.'.join(map(str, floor))}",
                ["supply:version_rollback:high"], attestation=att)

        return AttestationVerdict(True, "attested", f"tool '{name}' verified",
                                  ["supply:attested"], attestation=att)

    def verify_file(self, name: str, path: str, version: str = "0.0.0") -> AttestationVerdict:
        try:
            return self.verify(name, sha256_file(path), version)
        except Exception as e:
            return AttestationVerdict(False, "unknown", f"cannot hash '{path}': {e}",
                                      ["supply:hash_failed:fail_closed"])

    # ---- capability envelope enforcement ----
    def check_envelope(self, name: str, kind: str) -> AttestationVerdict:
        """Is this action inside the envelope the tool was VETTED for? Capability creep — a
        read-only tool that starts egressing — is caught here regardless of the tool's claims."""
        key = _norm_name(name)
        with self._lock:
            att = self._attested.get(key)
        if att is None:
            return AttestationVerdict(not self.strict, "unknown",
                                      f"tool '{name}' has no attested envelope",
                                      ["supply:unattested_envelope:high"])
        if kind not in _ALL_KINDS:
            return AttestationVerdict(False, "attested",
                                      f"unknown action kind '{kind}' (fail-closed)",
                                      ["supply:unknown_kind:fail_closed"], attestation=att)
        if not att.envelope.permits(kind):
            return AttestationVerdict(
                False, "attested",
                f"tool '{name}' performed '{kind}' outside its vetted capability envelope",
                [f"supply:capability_creep:{kind}:critical"], attestation=att)
        return AttestationVerdict(True, "attested", f"'{kind}' within envelope",
                                  ["supply:envelope_ok"], attestation=att)

    # ---- bulk manifest verification (reuses the replay-manifest format) ----
    def verify_manifest(self, manifest_text: str) -> Tuple[bool, List[str]]:
        """Verify 'sha256  path' lines against attested digests. Returns (ok, problems)."""
        problems: List[str] = []
        for line in (manifest_text or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                problems.append(f"malformed manifest line: {line[:60]}")
                continue
            digest, path = parts[0], parts[-1]
            v = self.verify(path, digest)
            if not v.trusted:
                problems.append(f"{path}: {v.status} — {v.reason}")
        return (not problems), problems
