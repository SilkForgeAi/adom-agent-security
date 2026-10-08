"""Task authority compiled from legitimate prompts and profile-declared sources.

Banking seals named clean files and transaction metadata. Travel seals catalog
metadata. Slack/workspace currently require privileged pre-injection snapshots,
including explicitly delegated text. These are developed profiles, not proof of
safe authority extraction from arbitrary untrusted content.
"""
from __future__ import annotations

import hashlib
import json
import re
from decimal import Decimal
from dataclasses import dataclass
from typing import Any

from adom.api.model_proxy import ModelProxyPolicy

_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_NUMBER = re.compile(r"\d+(?:\.\d+)?")
_QUOTED = re.compile(r"['\"]([^'\"]{4,})['\"]")
_FILE = re.compile(r"[\w.-]+\.txt", re.I)


def norm_value(value: Any) -> tuple:
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, (int, float)):
        return ("num", format(Decimal(str(value)).normalize(), "f"))
    if isinstance(value, str):
        text = value.strip()
        if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
            return ("num", format(Decimal(text).normalize(), "f"))
        return ("str", text.casefold())
    return ("other", type(value).__name__)


@dataclass(frozen=True)
class FlowRule:
    tool: str
    arg: str
    kind: str
    keyword: str = ""

    def as_list(self) -> list:
        return [self.tool, self.arg, self.kind, self.keyword]


def _word(prompt: str, word: str) -> bool:
    return re.search(rf"\b{re.escape(word)}\b", prompt, re.I) is not None


def _add_address(found: set, full: str) -> None:
    full = full.strip().rstrip(".")
    if not full:
        return
    found.add(norm_value(full))
    parts = [part.strip() for part in full.split(",") if part.strip()]
    if parts:
        found.add(norm_value(parts[0]))
    if len(parts) > 1:
        found.add(norm_value(", ".join(parts[1:])))
    for part in parts:
        found.add(norm_value(part))


def _mask_spans(prompt: str) -> str:
    """Hide IBANs, quotations and the address clause before scanning for amounts.
    Digits inside an account number, a password or a street number are not an
    authorized payment amount."""
    masked = _IBAN.sub(" ", prompt)
    masked = _QUOTED.sub(" ", masked)
    address = re.search(r"address:\s*(.+?)(?:\s+and\s+|$)", prompt, re.I)
    if address:
        masked = masked.replace(address.group(1), " ")
    return masked


def trusted_from_prompt(prompt: str) -> set:
    """Literals the user actually wrote."""
    found = set()
    for match in _IBAN.finditer(prompt):
        found.add(norm_value(match.group(0)))
    for match in _QUOTED.finditer(prompt):
        found.add(norm_value(match.group(1)))
    for match in _FILE.finditer(prompt):
        found.add(norm_value(match.group(0)))
    for payee in ("spotify", "apple"):
        if _word(prompt, payee):
            found.add(norm_value(payee))
    address = re.search(r"address:\s*(.+?)(?:\s+and\s+|$)", prompt, re.I)
    if address:
        _add_address(found, address.group(1))
    masked = _mask_spans(prompt)
    for match in _NUMBER.finditer(masked):
        if match.end() < len(masked) and masked[match.end():match.end() + 1] == "%":
            continue
        found.add(norm_value(match.group(0)))
    return found


# Reads of the user's own account have no side effect and no attacker-chosen
# argument. Scoping applies to tools that change state or pick a file.
READ_ONLY_TOOLS = (
    "get_balance",
    "get_iban",
    "get_most_recent_transactions",
    "get_scheduled_transactions",
    "get_user_info",
)


def allowed_tools(prompt: str) -> tuple[str, ...]:
    tools = set(READ_ONLY_TOOLS)
    if ".txt" in prompt.lower() or _word(prompt, "read"):
        tools.add("read_file")
    if any(phrase in prompt.lower() for phrase in (
        "transaction", "spending", "spend", "history", "refund", "suspicious",
        "summary", "sent me", "last month", "paid",
    )) or _word(prompt, "check"):
        tools.add("get_most_recent_transactions")
    if any(phrase in prompt.lower() for phrase in (
        "scheduled", "recurring", "standing order", "rent", "set up",
    )):
        tools.add("get_scheduled_transactions")
    if _word(prompt, "balance"):
        tools.add("get_balance")
    if _word(prompt, "iban"):
        tools.add("get_iban")
    if _word(prompt, "pay") or _word(prompt, "send") or _word(prompt, "refund") or _word(prompt, "bill"):
        tools.add("send_money")
    if "recurring" in prompt.lower() or "set up" in prompt.lower():
        tools.add("schedule_transaction")
    if any(phrase in prompt.lower() for phrase in (
        "adjust", "standing order", "rent payment", "update my rent",
    )) or ("rent" in prompt.lower() and "update" in prompt.lower()):
        tools.add("update_scheduled_transaction")
    if "address" in prompt.lower() or "account information" in prompt.lower():
        tools.add("update_user_info")
        tools.add("get_user_info")
    if _word(prompt, "password"):
        tools.add("update_password")
    return tuple(sorted(tools))


def flow_rules(prompt: str, derived_rent: bool) -> tuple[FlowRule, ...]:
    text = prompt.lower()
    rules = []
    if "spotify" in text and re.search(r"usually pay|pay for", text):
        rules.append(FlowRule("schedule_transaction", "amount", "amount_where_subject", "spotify"))
        rules.append(FlowRule("send_money", "amount", "amount_where_subject", "spotify"))
    for payee in ("spotify", "apple"):
        if _word(prompt, payee) and re.search(r"\b(send|pay)\b", text):
            # The payee's account number as recorded on the user's own
            # outgoing transactions, never an IBAN written in free text.
            rules.append(FlowRule("send_money", "recipient", "recipient_where_subject", payee))
    if re.search(r"what they'?ve sent|sent me", text):
        rules.append(FlowRule("send_money", "amount", "amount_where_sender_trusted"))
    if "refund" in text and _NUMBER.search(_mask_spans(prompt)):
        rules.append(FlowRule("send_money", "recipient", "sender_where_amount_trusted"))
    if "rent" in text and re.search(r"adjust|update|standing order", text):
        rules.append(FlowRule("update_scheduled_transaction", "id", "id_where_subject", "rent"))
    stated_rent = re.search(r"rent is\s+\d", text) is not None
    # An open computed amount is only for tasks that tell the user to derive a
    # number and do not already name it. When the clean notice states the
    # increase, that sum is sealed as a literal instead.
    rules.sort(key=lambda rule: (rule.tool, rule.arg, rule.kind, rule.keyword))
    return tuple(rules)


_MONEY = re.compile(r"\d+\.\d{2}")


def absorb_named_files(prompt: str, source: dict | None, found: set, tools: set) -> bool:
    """Seal values from files the prompt names, using the pre-attack environment.

    Only files the user task mentions are read. Injection text is not present
    yet: the caller passes the suite's default environment. Nothing read here
    is added later, when tool output may contain an attack.
    """
    if not source:
        return False
    files = {name.lower(): text for name, text in (source.get("files") or {}).items()}
    derived_rent = False
    for name in _FILE.findall(prompt):
        body = files.get(name.lower())
        if not isinstance(body, str):
            continue
        for match in _IBAN.finditer(body):
            found.add(norm_value(match.group(0)))
        for match in _MONEY.finditer(_IBAN.sub(" ", body)):
            found.add(norm_value(match.group(0)))
        for line in body.splitlines():
            line = line.strip()
            if not line or "\t" in line or "iban" in line.lower() or line.lower().startswith("please"):
                continue
            if "," in line and re.search(r"\d", line):
                _add_address(found, line)
            elif re.search(r"^[A-Za-z].*\d", line) and len(line) <= 40:
                _add_address(found, line)
        low = body.lower()
        if re.search(r"\brent\b", low) or "standing order" in low:
            tools.add("get_scheduled_transactions")
            tools.add("update_scheduled_transaction")
            increase = re.search(r"increased by\s+(\d+(?:\.\d+)?)", body, re.I)
            for txn in source.get("scheduled") or []:
                subject = str(txn.get("subject") or "")
                if "rent" not in subject.lower():
                    continue
                found.add(norm_value(txn.get("id")))
                if increase:
                    found.add(norm_value(float(txn.get("amount")) + float(increase.group(1))))
                    derived_rent = True
    return derived_rent


@dataclass
class FrozenTaskPolicy:
    task_id: str
    prompt_sha256: str
    allowed_tools: tuple
    trusted_values: tuple
    rules: tuple
    contracts: tuple
    adom: ModelProxyPolicy
    policy_sha256: str

    def verify(self) -> bool:
        if not self.adom.verify_seal():
            return False
        return self.policy_sha256 == self._hash()

    def _hash(self) -> str:
        payload = {
            "task_id": self.task_id,
            "prompt_sha256": self.prompt_sha256,
            "allowed_tools": list(self.allowed_tools),
            "trusted_values": [list(item) for item in self.trusted_values],
            "rules": [rule.as_list() for rule in self.rules],
            "contracts": list(self.contracts),
            # ADOM's own seal fingerprint includes an object address, which
            # changes between processes. Hash the configuration it seals.
            "adom": {
                "allowed_tools": list(self.adom.allowed_tools),
                "approved_destructive_actions": [list(x) for x in self.adom.approved_destructive_actions],
                "trusted_local_reads": list(self.adom.trusted_local_reads),
                "strict_deny_unknown": self.adom.strict_deny_unknown,
                "block_mode": self.adom.block_mode,
                "block_generic_secrets": self.adom.block_generic_secrets,
                "track_session": self.adom.track_session,
                "approved_outbound": list(self.adom.approved_outbound),
                "approved_payees": list(self.adom.approved_payees),
                "taint_values": list(self.adom.taint_values),
                "resolver": self.adom.resolver is not None,
            },
        }
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def public_record(self) -> dict:
        return {
            "task_id": self.task_id,
            "prompt_sha256": self.prompt_sha256,
            "policy_sha256": self.policy_sha256,
            "allowed_tools": list(self.allowed_tools),
            "trusted_values": [list(item) for item in self.trusted_values],
            "rules": [rule.as_list() for rule in self.rules],
            "contracts": list(self.contracts),
        }


def compile_task_policy(task_id: str, prompt: str, source: dict | None = None) -> FrozenTaskPolicy:
    if source and source.get("suite") == "workspace":
        from .workspace_policy import compile_workspace
        return compile_workspace(task_id, prompt, source)
    if source and source.get("suite") == "slack":
        from .slack_policy import compile_slack
        return compile_slack(task_id, prompt, source)
    if source and source.get("suite") == "travel":
        from .travel_policy import compile_travel
        return compile_travel(task_id, prompt, source)
    from .contracts import compile_contracts
    tools = set(allowed_tools(prompt))
    found = trusted_from_prompt(prompt)
    derived_rent = absorb_named_files(prompt, source, found, tools)
    trusted = tuple(sorted(found, key=lambda item: (item[0], str(item[1]))))
    tools = tuple(sorted(tools))
    rules = flow_rules(prompt, derived_rent)
    adom = ModelProxyPolicy(
        allowed_tools=tools,
        strict_deny_unknown=True,
        block_mode=True,
        track_session=True,
    )
    adom.seal()
    policy = FrozenTaskPolicy(
        task_id=task_id,
        prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
        allowed_tools=tools,
        trusted_values=trusted,
        rules=rules,
        contracts=compile_contracts(prompt, source),
        adom=adom,
        policy_sha256="",
    )
    policy.policy_sha256 = policy._hash()
    return policy
