"""Declared tool contracts: what a tool does is stated by the operator, not guessed (2026-11-10).

The policy in adom.api.model_proxy decides what kind of action a call is from substrings of
the tool's NAME ("pay", "send", "delete", ...). A money tool called `settle_invoice` is not
recognised as money, and once a tool is granted its arguments are mostly unconstrained.

A contract removes the guess. For each tool the operator declares:

  kind               read | write | network | spend | destructive | privileged | exec
  fields             every argument the tool accepts: type, required, enum, pattern, bounds.
                     Undeclared arguments are refused.
  network tools      which argument is the destination, the hosts it may name, the HTTP method
  spend tools        which arguments are amount and payee, the ceiling and the payees allowed
  requires_approval  defaults to True for spend, destructive, privileged and exec

Contracts only ever TIGHTEN. The kernel verdict still binds: a call that the policy blocks
stays blocked whatever its contract says. A contract cannot grant a tool, approve a payee the
policy refuses, or release anything. What it adds is: refusal of calls outside the declared
shape, the consequence class used for budgets and vetting envelopes, and a review requirement
for consequential tools whose names the heuristics would have waved through.

Operator-authored patterns are trusted input. Values are length-bounded before any pattern
runs. Python 3.9+, standard library only.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

KINDS = ("read", "write", "network", "spend", "destructive", "privileged", "exec")
_APPROVAL_DEFAULT = {"spend", "destructive", "privileged", "exec"}
_TYPES = ("string", "integer", "number", "boolean", "object", "array")
_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
_FIELD_KEYS = {"type", "required", "enum", "pattern", "max_length", "minimum", "maximum",
               "properties", "items", "max_items"}
_CONTRACT_KEYS = {"kind", "fields", "destination_field", "allowed_hosts", "method",
                  "amount_field", "max_amount", "payee_field", "allowed_payees",
                  "requires_approval"}


class ContractError(ValueError):
    """The contract DEFINITION is wrong. Raised at load time, never at decision time."""


@dataclass(frozen=True)
class FieldSpec:
    type: str
    required: bool = True
    enum: Optional[Tuple[Any, ...]] = None
    pattern: Optional[str] = None
    max_length: int = 4096
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    properties: Optional[Mapping[str, "FieldSpec"]] = None
    items: Optional["FieldSpec"] = None
    max_items: int = 256


@dataclass(frozen=True)
class ToolContract:
    name: str
    kind: str
    fields: Mapping[str, FieldSpec]
    destination_field: Optional[str] = None
    allowed_hosts: Tuple[str, ...] = ()
    method: str = "POST"
    amount_field: Optional[str] = None
    max_amount: Optional[float] = None
    payee_field: Optional[str] = None
    allowed_payees: Tuple[str, ...] = ()
    requires_approval: bool = False


@dataclass
class ContractResult:
    ok: bool
    kind: str = ""
    reason: str = ""
    signals: List[str] = field(default_factory=list)
    requires_approval: bool = False
    destination: str = ""
    method: str = "POST"
    amount: float = 0.0


def _field(tool: str, fname: str, raw: Any, _depth: int = 0) -> FieldSpec:
    if _depth > 8:
        raise ContractError(f"{tool}.{fname}: nested schema exceeds max depth 8")
    if not isinstance(raw, dict) or set(raw) - _FIELD_KEYS:
        raise ContractError(f"{tool}.{fname}: field spec has unknown keys or is not an object")
    typ = raw.get("type")
    if typ not in _TYPES:
        raise ContractError(f"{tool}.{fname}: type must be one of {_TYPES}")
    pattern = raw.get("pattern")
    if pattern is not None:
        if typ != "string" or not isinstance(pattern, str):
            raise ContractError(f"{tool}.{fname}: pattern applies to string fields only")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ContractError(f"{tool}.{fname}: bad pattern: {exc}") from None
    enum = raw.get("enum")
    if enum is not None and (not isinstance(enum, (list, tuple)) or not enum):
        raise ContractError(f"{tool}.{fname}: enum must be a non-empty list")
    max_length = raw.get("max_length", 4096)
    if type(max_length) is not int or not (0 < max_length <= 262144):
        raise ContractError(f"{tool}.{fname}: max_length out of range")
    for bound in ("minimum", "maximum"):
        b = raw.get(bound)
        if b is not None and (type(b) not in (int, float) or not math.isfinite(b)):
            raise ContractError(f"{tool}.{fname}: {bound} must be a finite number")
    props_raw = raw.get("properties")
    props = None
    if props_raw is not None:
        if typ != "object" or not isinstance(props_raw, dict):
            raise ContractError(f"{tool}.{fname}: properties apply to object fields only")
        props = MappingProxyType({k: _field(tool, f"{fname}.{k}", v, _depth + 1)
                                  for k, v in props_raw.items()})
    items_raw = raw.get("items")
    items = None
    if items_raw is not None:
        if typ != "array" or not isinstance(items_raw, dict):
            raise ContractError(f"{tool}.{fname}: items applies to array fields only")
        items = _field(tool, f"{fname}[]", items_raw, _depth + 1)
    max_items = raw.get("max_items", 256)
    if type(max_items) is not int or not (0 <= max_items <= 4096):
        raise ContractError(f"{tool}.{fname}: max_items out of range")
    return FieldSpec(typ, bool(raw.get("required", True)),
                     tuple(enum) if enum is not None else None, pattern, max_length,
                     raw.get("minimum"), raw.get("maximum"), props, items, max_items)


def _contract(name: str, raw: Any) -> ToolContract:
    if not isinstance(name, str) or not name or len(name) > 256:
        raise ContractError("tool name must be a non-empty string of at most 256 characters")
    if not isinstance(raw, dict) or set(raw) - _CONTRACT_KEYS:
        raise ContractError(f"{name}: contract has unknown keys or is not an object")
    kind = raw.get("kind")
    if kind not in KINDS:
        raise ContractError(f"{name}: kind must be one of {KINDS}")
    raw_fields = raw.get("fields")
    if not isinstance(raw_fields, dict):
        raise ContractError(f"{name}: fields must be an object (use {{}} for no arguments)")
    fields = {fn: _field(name, fn, fs) for fn, fs in raw_fields.items()}
    hosts = tuple(str(h).lower().strip() for h in raw.get("allowed_hosts", ()))
    payees = tuple(raw.get("allowed_payees", ()))
    method = str(raw.get("method", "POST")).upper()
    if method not in _METHODS:
        raise ContractError(f"{name}: method must be one of {_METHODS}")

    def need_field(key: str, types: Tuple[str, ...]) -> str:
        fn = raw.get(key)
        if fn not in fields or not fields[fn].required or fields[fn].type not in types:
            raise ContractError(f"{name}: {key} must name a required field of type {types}")
        return fn

    dest = amount = payee = None
    max_amount = None
    if kind == "network":
        dest = need_field("destination_field", ("string",))
        if not hosts or any(not h or "/" in h or "*" in h for h in hosts):
            raise ContractError(f"{name}: network tools need allowed_hosts (plain host names)")
    elif raw.get("destination_field") is not None or hosts:
        raise ContractError(f"{name}: only network tools declare a destination and hosts")
    if kind == "spend":
        amount = need_field("amount_field", ("integer", "number"))
        payee = need_field("payee_field", ("string",))
        max_amount = raw.get("max_amount")
        if type(max_amount) not in (int, float) or not math.isfinite(max_amount) or max_amount <= 0:
            raise ContractError(f"{name}: spend tools need a positive max_amount")
        if not payees or any(not isinstance(p, str) or not p for p in payees):
            raise ContractError(f"{name}: spend tools need allowed_payees")
    elif any(raw.get(k) is not None for k in ("amount_field", "payee_field", "max_amount")) or payees:
        raise ContractError(f"{name}: only spend tools declare amount and payee")
    approval = raw.get("requires_approval")
    if approval is None:
        approval = kind in _APPROVAL_DEFAULT
    elif type(approval) is not bool:
        raise ContractError(f"{name}: requires_approval must be true or false")
    return ToolContract(name, kind, MappingProxyType(dict(fields)), dest, hosts, method,
                        amount, float(max_amount) if max_amount is not None else None,
                        payee, payees, approval)


def _validate_value(fname: str, spec: FieldSpec, v: Any) -> Optional[str]:
    if not _type_ok(spec, v):
        return f"{fname} is not {spec.type}"
    if spec.type == "string":
        if len(v) > spec.max_length:
            return f"{fname} too long"
        if spec.pattern is not None and re.fullmatch(spec.pattern, v) is None:
            return f"{fname} does not match its pattern"
    if spec.type in ("integer", "number"):
        if spec.minimum is not None and v < spec.minimum:
            return f"{fname} below minimum"
        if spec.maximum is not None and v > spec.maximum:
            return f"{fname} above maximum"
    if spec.enum is not None and not any(type(v) is type(e) and v == e for e in spec.enum):
        return f"{fname} not an allowed value"
    if spec.type == "object" and spec.properties is not None:
        extra = sorted(set(v) - set(spec.properties))
        if extra:
            return f"{fname}: undeclared field {repr(extra[0])[:80]}"
        for subname, subspec in spec.properties.items():
            if subname not in v:
                if subspec.required:
                    return f"{fname}: missing {subname}"
                continue
            err = _validate_value(f"{fname}.{subname}", subspec, v[subname])
            if err:
                return err
    if spec.type == "array":
        if len(v) > spec.max_items:
            return f"{fname} exceeds max_items ({spec.max_items})"
        if spec.items is not None:
            for idx, elem in enumerate(v):
                err = _validate_value(f"{fname}[{idx}]", spec.items, elem)
                if err:
                    return err
    return None


def _type_ok(spec: FieldSpec, v: Any) -> bool:
    t = spec.type
    if t == "string":
        return type(v) is str
    if t == "boolean":
        return type(v) is bool
    if t == "integer":
        return type(v) is int
    if t == "number":
        return type(v) in (int, float) and (type(v) is int or math.isfinite(v))
    if t == "object":
        return type(v) is dict
    return type(v) in (list, tuple)


class ContractRegistry:
    """Immutable set of contracts with a fingerprint checked on every decision."""

    def __init__(self, spec: Mapping[str, Any]):
        if not isinstance(spec, Mapping):
            raise ContractError("contracts must be an object keyed by exact tool name")
        self._contracts: Mapping[str, ToolContract] = MappingProxyType(
            {name: _contract(name, raw) for name, raw in spec.items()})
        self._seal = self._fingerprint()

    @classmethod
    def from_file(cls, path) -> "ContractRegistry":
        with open(path, "r", encoding="utf-8") as f:
            return cls(json.load(f))

    def _fingerprint(self) -> str:
        parts = []
        for name in sorted(self._contracts):
            c = self._contracts[name]
            parts.append(repr((c.name, c.kind, sorted((k, repr(v)) for k, v in c.fields.items()),
                               c.destination_field, c.allowed_hosts, c.method, c.amount_field,
                               c.max_amount, c.payee_field, c.allowed_payees,
                               c.requires_approval)))
        return hashlib.sha256("\n".join(parts).encode()).hexdigest()

    @property
    def fingerprint(self) -> str:
        return self._seal

    def verify_seal(self) -> bool:
        try:
            return self._fingerprint() == self._seal
        except Exception:
            return False

    def get(self, name: str) -> Optional[ToolContract]:
        return self._contracts.get(name) if type(name) is str else None

    def kinds(self) -> Dict[str, str]:
        """{tool name: declared kind}, for ModelProxyPolicy(declared_kinds=...)."""
        return {name: c.kind for name, c in self._contracts.items()}

    def names(self) -> Tuple[str, ...]:
        return tuple(sorted(self._contracts))

    def check(self, name: str, args: Any) -> ContractResult:
        """Total: any internal error is a refusal."""
        try:
            return self._check(name, args)
        except Exception:
            return ContractResult(False, reason="tool contract check failed",
                                  signals=["contract:error_fail_closed"])

    def _check(self, name: str, args: Any) -> ContractResult:
        if not self.verify_seal():
            return ContractResult(False, reason="tool contracts changed after load",
                                  signals=["contract:seal_broken:critical"])
        c = self.get(name)
        if c is None:
            return ContractResult(False, reason="tool has no declared contract",
                                  signals=["contract:missing"])

        def bad(why: str) -> ContractResult:
            return ContractResult(False, c.kind, f"arguments outside the tool's contract: {why}",
                                  ["contract:violation:" + c.kind])

        if type(args) is not dict:
            return bad("arguments must be an object")
        extra = sorted(set(args) - set(c.fields))
        if extra:
            return bad("undeclared argument " + repr(extra[0])[:80])
        for fname, spec in c.fields.items():
            if fname not in args:
                if spec.required:
                    return bad(f"missing {fname}")
                continue
            err = _validate_value(fname, spec, args[fname])
            if err:
                return bad(err)

        res = ContractResult(True, c.kind, requires_approval=c.requires_approval, method=c.method)
        if c.kind == "network":
            # Lazy import: egress_proxy imports the policy module; keep this module standalone.
            from adom.enforcement.egress_proxy import host_of, host_matches
            dest = args[c.destination_field]
            parts = urlsplit(dest)
            if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
                return bad("destination must be an http(s) URL")
            if any(ch in dest for ch in "\\\r\n\t ") or "@" in parts.netloc:
                return bad("destination contains characters that confuse host parsing")
            if not host_matches(host_of(dest), c.allowed_hosts, allow_subdomains=False):
                return bad("destination host is not one this tool may reach")
            res.destination = dest
        if c.kind == "spend":
            amount = args[c.amount_field]
            if amount <= 0 or amount > c.max_amount:
                return bad("amount outside the tool's limit")
            if args[c.payee_field] not in c.allowed_payees:
                return bad("payee is not one this tool may pay")
            res.amount = float(amount)
        return res
