"""The one place a declared contract and an exact approval are applied to a kernel verdict.

Used by the generic gateway, the MCP gateway and the coding-agent hooks (through
action_tiers.screen), so the three paths cannot drift apart:

    frozen_args, verdict = action_kernel.screen_action(policy, name, args)
    verdict, contract, digest = review.resolve(name, frozen_args, verdict,
                                               contracts=..., approvals=..., agent_id=...)

Rules, in order:
  1. A contract (when a registry is supplied) can refuse the call or add a review
     requirement. It never loosens the kernel verdict.
  2. An exact approval can release a verdict that is blocked ONLY because review is
     required. A hard block does not carry the review signal and is never eligible.
  3. If no approval is on file the action is listed for a person, with its arguments.

`load_local()` reads the operator files the hooks use: ~/.adom/contracts.json and
~/.adom/approvals.sqlite with ~/.adom/approval.key.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Tuple

from adom.api.model_proxy import ProxyVerdict, _safe_label
from adom.enforcement.approvals import ApprovalStore, action_digest, shown_arguments

REVIEW = "action_kernel:review_required"

CONTRACTS_FILE = "contracts.json"
APPROVALS_DB = "approvals.sqlite"
APPROVAL_KEY = "approval.key"


def resolve(name: str, args: Any, v: ProxyVerdict, *, contracts: Any = None,
            approvals: Any = None, agent_id: str = "default-agent"
            ) -> Tuple[ProxyVerdict, Any, str]:
    """Returns (verdict, contract result or None, action digest or "").

    `args` is the kernel's frozen snapshot, or None when the kernel failed closed.
    """
    digest, contract = "", None
    if args is not None:
        try:
            digest = action_digest(agent_id, name, args)
        except Exception:
            digest = ""

    if contracts is not None and args is not None:
        contract = contracts.check(name, args)
        if contract.ok is not True:
            v = ProxyVerdict(action="block", reason=contract.reason or "outside tool contract",
                             signals=[s for s in v.signals if s != REVIEW] + list(contract.signals))
            contract = None
        elif contract.requires_approval and (v.action == "allow" or REVIEW in v.signals):
            # Marked even when the kernel already asked for review, so callers can tell an
            # operator-declared requirement from the kernel's generic outbound flag.
            v = ProxyVerdict(action="block",
                             reason=f"{contract.kind} tool requires exact trusted approval",
                             signals=[s for s in v.signals if s != REVIEW]
                             + [REVIEW, "contract:approval_required:" + contract.kind])

    if v.action == "block" and REVIEW in v.signals and args is not None \
            and approvals is not None and digest:
        try:
            approver = approvals.consume(digest)
        except Exception:
            approver = None
            v.signals.append("approval:store_error_fail_closed")
        if approver:
            v = ProxyVerdict(action="allow", reason="released by exact approval",
                             signals=[s for s in v.signals if s != REVIEW]
                             + ["approval:exact:consumed", "approval:by:" + _safe_label(approver, 60)])
        else:
            try:
                listed = approvals.request(digest, agent_id, _safe_label(name),
                                           _safe_label(v.reason or "", 300), shown_arguments(args))
            except Exception:
                listed = False
            v.signals.append("approval:pending" if listed else "approval:queue_unavailable")
            v.reason = (v.reason or "review required") + f" (approval id {digest})"
    return v, contract, digest


def load_local(state_dir: Optional[Path] = None) -> Tuple[Any, Any]:
    """(contracts, approvals) from the operator's state directory; None for what is absent.

    Fails loudly, never quietly: a contracts file that exists but does not load, or an
    approvals database without a usable key, raises. Callers in enforce mode deny on that.
    """
    from adom.enforcement.audit_chain import load_key
    from adom.enforcement.tool_contracts import ContractRegistry
    d = Path(state_dir) if state_dir else Path.home() / ".adom"
    contracts = approvals = None
    if (d / CONTRACTS_FILE).exists():
        contracts = ContractRegistry.from_file(d / CONTRACTS_FILE)
    if (d / APPROVALS_DB).exists():
        approvals = ApprovalStore(str(d / APPROVALS_DB), key=load_key(d / APPROVAL_KEY))
    return contracts, approvals
