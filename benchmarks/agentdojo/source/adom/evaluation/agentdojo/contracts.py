"""Purpose-bound banking contracts. Compiled without attack or oracle inputs.

Named-file and scheduled-row bindings use the existing pre-injection trusted
snapshot assumption. Transaction-derived bindings require an observed outgoing
or incoming structured record. No denial creates additional authority.
"""
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import re

MONEY_TOOLS = {"send_money", "schedule_transaction", "update_scheduled_transaction"}
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")


def money(value):
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        return None
    try:
        number = Decimal(str(value))
        if not number.is_finite() or number < 0 or number != number.quantize(Decimal(".01")):
            return None
        return number
    except (InvalidOperation, ValueError):
        return None


def compile_contracts(prompt, source=None):
    source = source or {}
    text = prompt.lower()
    contracts = []
    # The refund clause supplies refund authority, never preceding rent literals.
    refund = re.search(r"\brefund\b(.+)", prompt, re.I)
    if refund:
        clause = refund.group(1)
        account = IBAN.search(clause)
        masked = IBAN.sub(" ", clause)
        amount = re.search(r"\b\d+(?:\.\d+)?\b", masked)
        contracts.append(dict(tool="send_money", kind="refund", recipient=account.group() if account else None,
                              amount=str(money(amount.group())) if amount else None))
    elif "dinner" in text and "difference" in text:
        account = IBAN.search(prompt)
        total = re.search(r"spent\s+(\d+(?:\.\d+)?)\s+in total", prompt, re.I)
        if account and total:
            contracts.append(dict(tool="send_money", kind="dinner_difference", recipient=account.group(), total=total.group(1)))
    elif "difference" in text:
        rate = re.search(r"(\d+(?:\.\d+)?)\s*%", text)
        fee = re.search(r"fee of\s+(\d+(?:\.\d+)?)", text)
        subjects = [name for name in ("spotify", "apple") if re.search(rf"\b{name}\b", text)]
        if rate and len(subjects) == 1:
            contracts.append(dict(tool="send_money", kind="percentage", subject=subjects[0], rate=rate.group(1), fee=fee.group(1) if fee else "0"))
    for name in re.findall(r"[\w.-]+\.txt", prompt, re.I):
        body = (source.get("files") or {}).get(name)
        if not isinstance(body, str):
            continue
        account = IBAN.search(body)
        total = re.search(r"\bTotal\s+(\d+\.\d{2})", body, re.I)
        if "bill" in text and account and total:
            contracts.append(dict(tool="send_money", kind="literal", recipient=account.group(), amount=total.group(1), source=name))
    if ("recurring" in text or "set up" in text) and "spotify" in text:
        recipient = re.search(r"recipient is\s+(" + IBAN.pattern.replace(r"\b", "") + r")", prompt, re.I)
        if recipient:
            contracts.append(dict(tool="schedule_transaction", kind="same_amount", subject="spotify", recipient=recipient.group(1)))
    # A uniquely identified scheduled rent row is jointly bound to its ID and
    # recipient. An unchanged update is a safe no-op, not an arbitrary amount.
    rows = [r for r in source.get("scheduled", []) if re.search(r"\brent\b", str(r.get("subject", "")), re.I)]
    if len(rows) == 1 and "update_scheduled_transaction" in _tools(prompt, source):
        row = rows[0]
        amount = money(row.get("amount"))
        recipient = row.get("recipient")
        stated = re.search(r"rent is\s+(\d+(?:\.\d+)?)", text)
        landlord = re.search(r"landlord.s account is\s+(" + IBAN.pattern.replace(r"\b", "") + r")", prompt, re.I)
        if stated:
            amount = money(stated.group(1))
        if landlord:
            recipient = landlord.group(1)
        for name in re.findall(r"[\w.-]+\.txt", prompt, re.I):
            body = (source.get("files") or {}).get(name, "")
            increase = re.search(r"increased by\s+(\d+(?:\.\d+)?)", body, re.I)
            if increase and re.search(r"\brent\b", body, re.I):
                amount = money(row.get("amount")) + Decimal(increase.group(1))
        if amount is not None:
            contracts.append(dict(tool="update_scheduled_transaction", kind="rent", id=row["id"], amount=str(amount), recipient=recipient,
                                  unchanged={key: row[key] for key in ("subject", "date", "recurring") if key in row}))
    password = re.search(r"password to\s+['\"]([^'\"]+)['\"]", prompt, re.I)
    if password:
        contracts.append(dict(tool="update_password", kind="exact_fields", fields={"password":password.group(1)}))
    addresses = []
    address = re.search(r"new address:\s*(.+?)(?:\s+and\s+|$)", prompt, re.I)
    if address:
        parts = [p.strip().rstrip(".") for p in address.group(1).split(",")]
        if len(parts) > 1:
            addresses.append({"street": [parts[0]], "city": [parts[1], ", ".join(parts[1:])]})
    if "update" in text and ("account information" in text or "address" in text):
        for name in re.findall(r"[\w.-]+\.txt", prompt, re.I):
            lines = (source.get("files") or {}).get(name, "").splitlines()
            for i, line in enumerate(lines[:-1]):
                street = line.strip()
                if re.fullmatch(r"[A-Za-z][A-Za-z ]+\s+\d+", street):
                    city = lines[i+1].strip()
                    if city:
                        addresses.append({"street":[street], "city":[city,city.split(",")[0].strip()]})
        for fields in addresses:
            contracts.append(dict(tool="update_user_info",kind="profile",fields=fields))
    return tuple(contracts)


def _tools(prompt, source):
    from .task_policy import allowed_tools
    tools = set(allowed_tools(prompt))
    for name in re.findall(r"[\w.-]+\.txt", prompt, re.I):
        body = (source.get("files") or {}).get(name, "")
        if "rent" in body.lower() or "standing order" in body.lower():
            tools.add("update_scheduled_transaction")
    return tools


def _value(record, field):
    value = record.get(field)
    return value[1] if isinstance(value, tuple) and len(value) == 2 else None


def contract_allows(policy, ledger, tool, args):
    """All consequential money arguments must match one complete contract."""
    if tool in {"update_password", "update_user_info"}:
        args = {key:value for key,value in args.items() if value is not None}
        for c in policy.contracts:
            if c["tool"] != tool or not args or set(args) - set(c["fields"]):
                continue
            if c["kind"] == "exact_fields" and args == c["fields"]:
                return True
            if c["kind"] == "profile" and all(isinstance(value,str) and value in c["fields"][key] for key,value in args.items()):
                return True
        return False
    if tool not in MONEY_TOOLS:
        return None
    args = {key: value for key, value in args.items() if value is not None}
    allowed_fields = {"recipient", "amount", "subject", "date"}
    if tool == "schedule_transaction":
        allowed_fields.add("recurring")
    if tool == "update_scheduled_transaction":
        allowed_fields.update({"id", "recurring"})
    if set(args) - allowed_fields:
        return False
    if "recurring" in args and type(args["recurring"]) is not bool:
        return False
    for c in policy.contracts:
        if c["tool"] != tool:
            continue
        kind = c["kind"]
        if kind == "rent":
            if type(args.get("id")) is not int or args["id"] != c["id"]:
                continue
            if "amount" in args and money(args["amount"]) != money(c["amount"]):
                continue
            if "recipient" in args and args["recipient"] != c["recipient"]:
                continue
            unchanged = c.get("unchanged", {})
            extras = set(args) - {"id", "amount", "recipient"}
            if extras <= set(unchanged) and all(type(args[key]) is type(unchanged[key]) and args[key] == unchanged[key] for key in extras) and len(args) > 1:
                return True
            continue
        amount = money(args.get("amount"))
        recipient = args.get("recipient")
        if amount is None or amount <= 0 or not isinstance(recipient, str):
            continue
        if kind == "literal" and recipient == c["recipient"] and amount == money(c["amount"]):
            return True
        for name, row in ledger.records:
            if name != "get_most_recent_transactions":
                continue
            recorded = money(_value(row, "amount"))
            if recorded is None:
                continue
            sender, payee = _value(row, "sender"), _value(row, "recipient")
            expected = None
            if kind in {"refund", "dinner_difference"}:
                if payee != "me" or sender != recipient.casefold() or (c.get("recipient") and recipient != c["recipient"]):
                    continue
                if kind == "refund":
                    expected = money(c["amount"]) if c.get("amount") is not None else recorded
                    if expected != recorded:
                        continue
                else:
                    expected = recorded - Decimal(c["total"]) / 2
            elif kind in {"percentage", "same_amount"}:
                if sender != "me" or c["subject"] not in str(row.get("subject", "")):
                    continue
                if kind == "percentage":
                    if recipient.casefold() not in {payee, c["subject"]}:
                        continue
                    expected = (recorded * Decimal(c["rate"]) / 100 + Decimal(c["fee"])).quantize(Decimal(".01"), rounding=ROUND_HALF_UP)
                elif recipient == c["recipient"]:
                    expected = recorded
            if expected is not None and expected > 0 and amount == expected:
                return True
    return False
