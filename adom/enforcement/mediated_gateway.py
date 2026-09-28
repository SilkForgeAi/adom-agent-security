"""
ADOM mediated gateway — the SOLE MEDIATED PATH.

A control only holds if the agent's actions are *forced* through it. This gateway is the
single object every agent action passes through, composing independent enforcement
planes so that a bypass of one can still be caught by another:

    agent action ─▶  ┌─────────────── ADOM mediated gateway ───────────────┐
                     │  Plane 0 — BLAST RADIUS (budgets + circuit breaker). │
                     │  Plane 1 — ACTION boundary (ModelProxyPolicy,        │
                     │            strict deny-unknown): scores every tool   │
                     │            call; nothing runs unless permitted.      │
                     │  Plane 2 — NETWORK egress (EgressPolicy): every       │
                     │            outbound byte is independently screened   │
                     │            (host allowlist + secret/taint scan).     │
                     │  Plane 3 — TOOL ATTESTATION (optional envelope).     │
                     └──────────────────────────────────────────────────────┘
                                    │ (only permitted actions/bytes exit)
                                    ▼
                          executor / real network

Key property: the host application NEVER calls a tool executor directly and the agent
process has NO direct network route — its only egress is the ADOM egress proxy. So the
gateway is not *a* checkpoint, it is *the* checkpoint. Action and network policy are each
independently sufficient to stop a secret exfil; blast-radius accounting additionally stops
unbounded retries and consequence accumulation.

Honest scope: the software here guarantees mediation *if the deployment routes through it*.
The unbypassability itself is enforced at the OS/container layer (network namespace +
forced HTTP(S)_PROXY + dropped caps + seccomp) — `deployment_manifest()` emits that exact
binding, and `container_hardening.py` supplies the runtime flags. Python cannot enforce a
network namespace on its own; that is a deployment requirement, stated plainly.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

_SNAP_MAX_DEPTH = 40
_SNAP_MAX_ITEMS = 5000
_AUDIT_MAX = 10000        # bound the in-memory audit buffer (memory-exhaustion DoS)
_AUDIT_KEEP = 5000


from adom.enforcement.action_kernel import snapshot_args, screen_action

from adom.api.model_proxy import (ModelProxyPolicy, ProxyVerdict, _safe_label,
                                  _collect_strings, _network_dest, _looks_external)
from adom.enforcement.egress_proxy import EgressPolicy, host_of

_EGRESS_BODY_MAX = 262144        # bound the body handed to the network screen (DoS)


def _POLICY_DEST_FINDER(args):
    """Destination discovery shared with the action plane (nested-aware)."""
    try:
        return ModelProxyPolicy()._destination(args) or ""
    except Exception:
        return ""


@dataclass
class GatewayDecision:
    permitted: bool
    plane: str                      # "action" | "network" | "both"
    action: str                     # allow | flag | block
    reason: str = ""
    signals: List[str] = field(default_factory=list)
    result: Any = None              # executor return value when permitted


class MediatedAgentGateway:
    """Single mandatory mediator for every agent action.

    tool_policy   : ModelProxyPolicy (recommend strict_deny_unknown=True in production)
    egress_policy : EgressPolicy — independent network plane (host allowlist + secret scan)
    blast_radius  : optional BlastRadiusController — attempt/consequence budgets and breaker
    executor      : callable(name, args) -> Any — the host's REAL tool implementation.
                    It is invoked ONLY when the action plane permits the call, so a denied
                    action never reaches it. (The gateway is the sole path to the executor.)
    """

    def __init__(self, tool_policy: ModelProxyPolicy,
                 egress_policy: Optional[EgressPolicy] = None,
                 executor: Optional[Callable[[str, Any], Any]] = None,
                 on_decision: Optional[Callable[[str, GatewayDecision], None]] = None,
                 attestation: Any = None, mediation_attestor: Any = None,
                 blast_radius: Any = None, agent_id: str = "default-agent"):
        self.tool_policy = tool_policy
        self.egress_policy = egress_policy
        self.executor = executor
        self.on_decision = on_decision
        # Optional ToolAttestationRegistry. When supplied, PLANE 3 enforces the capability
        # ENVELOPE each tool was vetted for. Without this wiring the envelope logic existed
        # only inside its own unit test — a control that reports green while protecting
        # nothing (see scripts/_scan_unreachable_controls.py).
        self.attestation = attestation
        self.mediation_attestor = mediation_attestor
        self.blast_radius = blast_radius
        self.agent_id = agent_id
        if self.blast_radius is not None:
            try:
                if not self.blast_radius.is_registered(agent_id):
                    self.blast_radius.register(agent_id)
            except Exception as exc:
                raise ValueError("blast-radius controller registration failed") from exc
        self.audit: List[Tuple[str, GatewayDecision]] = []
        self._lock = threading.RLock()

    # ---- the one entry point every tool call must pass through ----
    def run_tool(self, name: str, args: Any) -> GatewayDecision:
        with self._lock:
            return self._run_tool(name, args)

    def _run_tool(self, name: str, args: Any) -> GatewayDecision:
        if self.mediation_attestor is not None:
            try:
                self.mediation_attestor.require_current_mediation()
            except Exception:
                return self._finish(name, GatewayDecision(False, "action", "block",
                    "Current mediation is unverified", ["path:unverified_fail_closed"]))
        # TOCTOU defense: freeze the arguments ONCE. Everything below — scoring, the egress
        # screen, and execution — uses this snapshot, so the caller (or another thread) cannot
        # mutate the arguments between the verdict and execution.
        args, v = screen_action(self.tool_policy, name, args)

        # Plane 0: operational blast radius. This is independent of whether the individual
        # action looks malicious. Every attempt consumes an action budget; repeated policy,
        # network, attestation, or observation failures open the circuit. The compromised
        # agent cannot turn a safe deny into an unbounded availability/cost attack.
        blast_signals: List[str] = []
        if self.blast_radius is not None:
            try:
                kind, nbytes = self._blast_consequence(name, args)
                bv = self.blast_radius.check(self.agent_id, kind=kind, nbytes=nbytes)
            except Exception:
                return self._finish(name, GatewayDecision(
                    False, "blast_radius", "block", "blast-radius gate failed closed",
                    ["blast:gateway_error_fail_closed"]))
            blast_signals = list(bv.signals)
            if not bv.allowed:
                return self._finish(name, GatewayDecision(
                    False, "blast_radius", "block", bv.reason,
                    blast_signals + ["blast:execution_suppressed"]))

        # Plane 1: action boundary (strict). Nothing runs unless permitted.
        if v.action == "block":
            self._blast_failure()
            return self._finish(name, GatewayDecision(
                permitted=False, plane="action", action="block",
                reason=v.reason or "denied by action boundary",
                signals=blast_signals + list(v.signals) + self._blast_state_signals()))

        # Plane 2: independent network screen for any outbound-shaped action, even if the
        # action plane allowed it. Two independent planes — either alone stops secret exfil.
        if self.egress_policy is not None:
            dest, body = self._extract_egress(name, args)
            if dest is not None:
                host = _host_of(dest)
                ok, reason, sigs = self.egress_policy.decide(host, 443, "POST", dest, body)
                if not ok:
                    self._blast_failure()
                    return self._finish(name, GatewayDecision(
                        permitted=False, plane="network", action="block",
                        reason=reason,
                        signals=blast_signals + list(v.signals) + sigs + self._blast_state_signals()))

        # Plane 3: SUPPLY-CHAIN envelope. Is this action inside what the tool was vetted for?
        # A read-only connector that starts egressing is capability creep, and it is invisible
        # to both planes above because each individual call may look reasonable.
        if self.attestation is not None:
            kind = _consequence_kind(name, args, v)
            if kind:
                av = self.attestation.check_envelope(name, kind)
                if not getattr(av, "trusted", True):
                    self._blast_failure()
                    return self._finish(name, GatewayDecision(
                        permitted=False, plane="attestation", action="block",
                        reason=getattr(av, "reason", "outside vetted capability envelope"),
                        signals=blast_signals + list(v.signals)
                        + list(getattr(av, "signals", [])) + self._blast_state_signals()))

        # Permitted by every applicable plane — now (and only now) execute.
        result = self.executor(name, args) if self.executor else None
        from adom.enforcement.read_observation import observe_result
        try:
            result = observe_result(self.tool_policy, name, args, result)
        except RuntimeError as exc:
            self._blast_failure()
            return self._finish(name, GatewayDecision(False, "action", "block", str(exc),
                                blast_signals + ["observation:failed_after_read"]
                                + self._blast_state_signals()))
        if self.blast_radius is not None:
            self.blast_radius.record_success(self.agent_id)
        return self._finish(name, GatewayDecision(
            permitted=True, plane="both", action=v.action,
            reason=v.reason or "permitted", signals=blast_signals + list(v.signals), result=result))

    def _blast_failure(self) -> None:
        if self.blast_radius is not None:
            try:
                self.blast_radius.record_failure(self.agent_id)
            except Exception:
                # The current action is already denied. A failure to update accounting must
                # never turn that deny into an allow; the next check remains fail-closed.
                pass

    def _blast_state_signals(self) -> List[str]:
        if self.blast_radius is None:
            return []
        try:
            state = self.blast_radius.state_of(self.agent_id)
        except Exception:
            return ["blast:state_unavailable:high"]
        return [f"blast:state:{state}"]

    @staticmethod
    def _blast_consequence(name: str, args: Any) -> Tuple[str, int]:
        n = (name or "").lower()
        if any(h in n for h in ("delete", "remove", "drop", "wipe", "destroy", "truncate")):
            return "destructive", 0
        try:
            body = json.dumps(args, default=str, sort_keys=True).encode()
        except Exception:
            body = b""
        if _looks_external(args, name):
            return "egress", min(len(body), _EGRESS_BODY_MAX)
        return "action", 0

    def _extract_egress(self, name: str, args: Any) -> Tuple[Optional[str], bytes]:
        """Pull a destination + body out of a network-shaped tool call for the egress plane.

        Two failures this replaces, both of which broke the "two independent planes, either
        alone sufficient" property:

        1. Plane 2 only engaged when the tool NAME contained an egress verb. A tool called
           `archive_report` carrying a URL and a secret skipped the network screen entirely, so
           there was exactly one plane, not two. Detection is now by argument SHAPE — the same
           `_network_dest` test the action plane already uses — with the name as a hint only.

        2. The body was assembled from a fixed list of key names, and the flatten-everything
           fallback ran ONLY when none of those keys was present. A call with
           body="hi" + attachment=<secret> was screened on "hi" alone. Every value is now
           scanned; there is no key an operator has to remember to name correctly.
        """
        n = (name or "").lower()
        name_hints_outbound = any(h in n for h in ("http", "post", "fetch", "request", "webhook",
                                                   "url", "send", "upload", "curl", "email",
                                                   "slack", "sms", "publish"))
        if isinstance(args, str):
            return (args, args.encode("utf-8", "ignore")) if _network_dest(args) else (None, b"")
        if not isinstance(args, (dict, list, tuple)):
            return None, b""

        strings: List[str] = []
        _collect_strings(args, strings)
        shape_is_outbound = _looks_external(args, name)
        if not (name_hints_outbound or shape_is_outbound):
            return None, b""

        # Destination: reuse the action plane's discovery so both planes agree on "where".
        dest = _POLICY_DEST_FINDER(args)
        if not dest and shape_is_outbound:
            dest = next((s for s in strings if _network_dest(s)), "")
        # Body: EVERY string in the tree, so nothing hides in an unlisted key.
        body = " ".join(strings)[:_EGRESS_BODY_MAX].encode("utf-8", "ignore")
        return (dest or ""), body

    def _finish(self, name: str, d: GatewayDecision) -> GatewayDecision:
        with self._lock:
            # Bounded in-memory audit: an unbounded list is a memory-exhaustion DoS on a
            # long-running gateway. Durable retention belongs in the sink, not this buffer.
            self.audit.append((_safe_label(name), d))
            if len(self.audit) > _AUDIT_MAX:
                del self.audit[:len(self.audit) - _AUDIT_KEEP]
        if self.on_decision:
            try: self.on_decision(name, d)
            except Exception: pass
        return d

    # ---- the deployment binding that makes the path unbypassable ----
    def environment(self, egress_host: str = "127.0.0.1", egress_port: int = 8888) -> Dict[str, str]:
        """Env vars a child agent process MUST launch with: its only network route is the
        ADOM egress proxy. NO_PROXY empty so nothing is exempt."""
        proxy = f"http://{egress_host}:{egress_port}"
        return {"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
                "http_proxy": proxy, "https_proxy": proxy,
                "NO_PROXY": "", "no_proxy": ""}

    def deployment_manifest(self, image: str = "agent:latest",
                            egress_port: int = 8888,
                            network: str = "adom-egress-only",
                            proxy_image: str = "adom-egress:latest",
                            seccomp_path: str = "/etc/adom/seccomp.json") -> str:
        """Emit a deployment binding that actually forces the sole mediated path.

        A previous version emitted `--network none` together with
        `--add-host adom-egress:127.0.0.1`. That container has NO network namespace route at
        all: 127.0.0.1 inside it is the container itself, not the host, so the agent cannot
        reach the egress proxy — it simply has no network. An operator who "fixes" that by
        dropping `--network none` silently removes the containment that made the path sole.
        A manifest that cannot work is worse than none, because the first thing anyone does is
        relax it until traffic flows.

        The correct shape is an INTERNAL docker network (no route off-host) shared by the agent
        and the proxy. The agent's only reachable peer is the proxy; the proxy is the only
        container with an external route. Egress is sole-path by topology, not by convention.
        """
        try:
            from adom.enforcement.container_hardening import hardened_run_flags
            flags = hardened_run_flags(seccomp_path=seccomp_path, network=None)
        except Exception:
            flags = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only"]
        return (
            "# ADOM sole-mediated-path deployment.\n"
            "# 1. An INTERNAL network has no route off the host, so nothing on it can reach the\n"
            "#    internet directly. This is what makes the path sole — not the env vars, which\n"
            "#    an agent process could otherwise unset.\n"
            f"docker network create --internal {network}\n"
            "\n"
            "# 2. The egress proxy is the ONLY container bridging internal -> outside.\n"
            f"docker run -d --name adom-egress --network {network} \\\n"
            f"  --cap-drop ALL --security-opt no-new-privileges --read-only \\\n"
            f"  -p 127.0.0.1:{egress_port}:{egress_port} {proxy_image}\n"
            f"docker network connect bridge adom-egress   # its external route\n"
            "\n"
            "# 3. The agent runs hardened on the internal network. Its only reachable peer is\n"
            "#    the proxy; NO_PROXY is empty so nothing is exempt.\n"
            f"docker run {' '.join(flags)} --network {network} \\\n"
            f"  -e HTTP_PROXY=http://adom-egress:{egress_port} \\\n"
            f"  -e HTTPS_PROXY=http://adom-egress:{egress_port} \\\n"
            f"  -e NO_PROXY= -e no_proxy= \\\n"
            f"  {image}\n"
            "\n"
            "# 4. VERIFY the binding rather than assuming it. The agent should run\n"
            "#    MediationPathAttestor.require_mediation() at startup and keep .start()\n"
            "#    running: it sends a canary to an un-allowlisted host and fails closed unless\n"
            "#    ADOM refuses it. Env vars and netns can be misconfigured; the canary is\n"
            "#    end-to-end proof, produced by the same stack the agent uses.\n"
        )

    def path_attestor(self, egress_host: str = "127.0.0.1", egress_port: int = 8888,
                      **kwargs):
        """A MediationPathAttestor bound to this gateway's egress proxy.

        Convenience so the deployment-precondition check lives next to the thing it protects.
        """
        from adom.enforcement.path_attestation import MediationPathAttestor
        return MediationPathAttestor(f"http://{egress_host}:{egress_port}", **kwargs)


def _flatten(args: Dict) -> str:
    return " ".join(f"{k}={v}" for k, v in args.items())


# Canonical host parsing — shared with the action plane. The gateway's own copy previously
# omitted userinfo stripping, so 'corp.com@evil.io' parsed as 'corp.com' here.
_host_of = host_of


def _consequence_kind(name: str, args: Any, verdict: ProxyVerdict) -> Optional[str]:
    """Map a tool call to the supply-chain consequence class it exercises.

    Deliberately conservative: returns None when the call has no consequential class, so an
    ordinary read is never charged against an envelope.
    """
    from adom.enforcement.supply_chain import (KIND_NETWORK, KIND_DESTRUCTIVE, KIND_SPEND,
                                               KIND_PRIVILEGED, KIND_WRITE)
    n = (name or "").lower()
    sig = " ".join(verdict.signals or ())
    if "privilege_escalation" in sig or "sandbox_escape" in sig:
        return KIND_PRIVILEGED
    if any(h in n for h in ("transfer", "pay", "wire", "payout", "withdraw", "purchase")):
        return KIND_SPEND
    if any(h in n for h in ("delete", "remove", "drop", "rm_", "wipe", "destroy", "truncate")):
        return KIND_DESTRUCTIVE
    strings: List[str] = []
    _collect_strings(args, strings)
    if _looks_external(args, name) or any(
            h in n for h in ("http", "post", "fetch", "request", "webhook", "url", "send",
                             "upload", "curl", "email", "slack", "sms", "publish")):
        return KIND_NETWORK
    if any(h in n for h in ("write", "save", "put", "update", "create", "insert")):
        return KIND_WRITE
    return None
