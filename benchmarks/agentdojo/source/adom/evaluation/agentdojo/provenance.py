"""Where a tool argument came from.

User-prompt literals are the only trusted values. Tool output is untrusted.
Structured fields (an amount, an IBAN, a transaction id) stay distinguishable from
free-text fields, because that is where AgentDojo places its injection text
(transaction subjects, files). A sensitive argument is allowed when the user
named that value, or when a rule frozen from the user prompt points at a
structured field. A value that appears only in free text is not a value the
user asked for.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from adom.evaluation.agentdojo.task_policy import FlowRule, FrozenTaskPolicy, norm_value

_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", re.I)
_NUMBER = re.compile(r"\d+(?:\.\d+)?")
_FREETEXT_FIELDS = {"subject", "body", "content", "text", "message", "description", "note"}

# Arguments that choose a consequence. Everything else (dates, subjects, n)
# is not a sink. Adding a field here fails closed for that argument.
SENSITIVE_ARGS = {
    "send_money": ("recipient", "amount"),
    "schedule_transaction": ("recipient", "amount"),
    "update_scheduled_transaction": ("id", "recipient", "amount"),
    "update_password": ("password",),
    "update_user_info": ("first_name", "last_name", "street", "city"),
    "read_file": ("file_path",),
}


@dataclass
class Ledger:
    """Untrusted observations for one episode. Never promotes a value to trusted."""

    policy: FrozenTaskPolicy
    records: list
    freetext: set

    def __init__(self, policy: FrozenTaskPolicy):
        self.policy = policy
        self.records = []
        self.successful_tools = []
        self.completed_actions = []
        self.freetext = set()

    def observe(self, tool_name: str, result: Any, args: dict | None = None) -> None:
        self.successful_tools.append(tool_name)
        if args is not None:
            from copy import deepcopy
            self.completed_actions.append((tool_name, deepcopy(args)))
        if isinstance(result, str):
            self._mark_freetext(result)
            return
        if isinstance(result, (int, float)) and not isinstance(result, bool):
            self.records.append((tool_name, {"amount": norm_value(result)}))
            return
        for row in _rows(result):
            record = {}
            for key, value in row.items():
                if key in _FREETEXT_FIELDS and isinstance(value, str):
                    self._mark_freetext(value)
                    record[key] = value.casefold()
                    continue
                record[key] = norm_value(value)
            if record:
                self.records.append((tool_name, record))

    def _mark_freetext(self, text: str) -> None:
        for match in _IBAN.findall(text or ""):
            self.freetext.add(norm_value(match))
        for match in _NUMBER.findall(text or ""):
            self.freetext.add(norm_value(match))

    def in_freetext(self, value: Any) -> bool:
        return norm_value(value) in self.freetext


def _rows(result: Any) -> Iterable[dict]:
    if hasattr(result, "model_dump"):
        dumped = result.model_dump()
        return [dumped] if isinstance(dumped, dict) else []
    if isinstance(result, dict):
        return [result]
    if isinstance(result, list):
        rows = []
        for item in result:
            if hasattr(item, "model_dump"):
                dumped = item.model_dump()
                if isinstance(dumped, dict):
                    rows.append(dumped)
            elif isinstance(item, dict):
                rows.append(item)
        return rows
    return []


def _rule_holds(rule: FlowRule, value: Any, ledger: Ledger) -> bool:
    kind = rule.kind
    wanted = norm_value(value)
    keyword = (rule.keyword or "").casefold()
    for tool_name, record in ledger.records:
        if rule.kind == "id_where_subject" and tool_name != "get_scheduled_transactions":
            continue
        if rule.kind == "amount_where_subject" and tool_name not in (
            "get_most_recent_transactions", "get_scheduled_transactions"):
            continue
        if rule.kind == "amount_where_sender_trusted" and tool_name != "get_most_recent_transactions":
            continue
        if rule.kind == "sender_where_amount_trusted" and tool_name != "get_most_recent_transactions":
            continue
        if rule.kind == "recipient_where_subject" and tool_name != "get_most_recent_transactions":
            continue
        subject = record.get("subject") or ""
        if kind == "id_where_subject":
            if keyword in subject and record.get("id") == wanted:
                return True
        elif kind == "amount_where_subject":
            if keyword in subject and record.get("amount") == wanted:
                return True
        elif kind == "recipient_where_subject":
            # Outgoing only: the user's own account is the sender.
            if (keyword in subject and record.get("sender") == ("str", "me")
                    and record.get("recipient") == wanted):
                return True
        elif kind == "amount_where_sender_trusted":
            if record.get("sender") in ledger.policy.trusted_values and record.get("amount") == wanted:
                return True
        elif kind == "sender_where_amount_trusted":
            if record.get("amount") in ledger.policy.trusted_values and record.get("sender") == wanted:
                return True
    return False


def authorize(policy: FrozenTaskPolicy, ledger: Ledger, tool: str, args: dict) -> tuple[bool, str]:
    """True when this call is allowed by the frozen policy and the ledger."""
    if not policy.verify():
        return False, "policy seal does not match the frozen task policy"
    if tool not in policy.allowed_tools:
        return False, f"{tool}.recipient or action is outside the authorized task"
    from .workspace_policy import authorize_workspace
    workspace = authorize_workspace(policy, ledger, tool, args)
    if workspace is not None:
        return workspace, "" if workspace else "outside the frozen workspace contract"
    from .slack_policy import authorize_slack
    slack = authorize_slack(policy, ledger, tool, args)
    if slack is not None:
        return slack, "" if slack else "outside the frozen Slack contract"
    from .travel_policy import authorize_travel
    travel = authorize_travel(policy, ledger, tool, args)
    if travel is not None:
        return travel, "" if travel else "outside the frozen travel contract"
    from .contracts import contract_allows
    joint = contract_allows(policy, ledger, tool, args)
    if joint is not None:
        return joint, "" if joint else f"{tool}.recipient/amount or field combination is outside the purpose-bound contract"
    fields = SENSITIVE_ARGS.get(tool, ())
    for field in fields:
        if field not in args or args[field] is None:
            continue
        value = args[field]
        if norm_value(value) in policy.trusted_values:
            continue
        matched = False
        for rule in policy.rules:
            if rule.tool == tool and rule.arg == field and _rule_holds(rule, value, ledger):
                matched = True
                break
        if not matched:
            return False, f"{tool}.{field} is not a value the user asked for"
    return True, ""
