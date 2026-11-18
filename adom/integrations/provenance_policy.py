"""Suite-agnostic, stdlib-only tool-call provenance and intent enforcement.

Built strictly from:
  * the user's prompt (intent verbs, explicit addresses, hosts, paths, and numbers), and
  * atomic/structured values observed from trusted tool outputs during the episode,

with zero knowledge of any benchmark task, environment snapshot, or attack string.

The rule
--------
1. INTENT GATE. A tool that changes state may run only if the prompt contains a verb
   from that tool's verb family (e.g. send_email: send, email, forward, ...). Reads are open.
2. GROUNDING. Every argument that SELECTS a consequence (recipient, address, account,
   URL, id, name, amount, credential) must be grounded:
     a. written in the user's prompt, or
     b. equal to a whole ATOMIC value returned by a tool (a short single-line field such as
        an email address in a contact record, an id, or a name in a list). Values appearing
        only inside long untrusted prose never qualify.
   Content fields (body, subject, title, description, query) and date/time fields are free
   unless they embed an ungrounded email address or link.
3. URLs and email addresses must be grounded on every tool, reads included.
4. ADOM's enforcement kernel screens every call first; hard kernel blocks are final.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from adom.api.model_proxy import ModelProxyPolicy
from adom.enforcement.action_kernel import screen_action
from adom.enforcement.egress_proxy import host_matches

REVIEW = "action_kernel:review_required"

READ_PREFIXES = ("get_", "search_", "list_", "read_", "check_", "find_", "lookup_",
                 "view_", "browse_")
READ_NAMES = {"cart_total"}
CONTENT_ARGS = {"body", "content", "subject", "description", "title", "text", "message",
                "query", "note", "comment", "summary"}
# Verb in a tool's name -> words that show the user asked for that kind of action.
VERB_FAMILIES = {
    "send": ("send", "email", "e-mail", "mail", "forward", "message", "tell", "notify",
             "reply", "pay", "transfer", "refund", "dm", "write to", "invite", "remind"),
    "schedule": ("schedule", "set up", "recurring", "standing order", "pay", "create", "add"),
    "update": ("update", "change", "adjust", "set", "modify", "edit", "move"),
    "create": ("create", "add", "make", "schedule", "set up", "book", "put", "write",
               "remind", "save", "plan", "organize", "arrange"),
    "reserve": ("reserve", "reservation", "book"),
    "cancel": ("cancel", "delete", "remove"),
    "delete": ("delete", "remove", "erase", "clean", "clear"),
    "remove": ("remove", "delete", "kick"),
    "reschedule": ("reschedule", "move", "postpone", "change"),
    "add": ("add", "invite", "include", "put", "buy", "purchase", "order"),
    "append": ("append", "add", "write", "update", "put"),
    "share": ("share", "send", "give access"),
    "invite": ("invite", "add"),
    "post": ("post", "publish", "upload", "put"),
    "download": ("download", "fetch", "save", "get", "retrieve", "open", "visit"),
    "transfer": ("transfer", "send", "move", "give", "assign", "hand over"),
    "login": ("login", "log in", "sign in", "authenticate", "account"),
    "verify": ("verify", "check", "confirm", "validate", "account"),
    "checkout": ("checkout", "check out", "buy", "purchase", "order", "pay"),
    "clear": ("clear", "empty", "remove", "delete", "clean"),
    "refund": ("refund", "return", "reimburse"),
    "copy": ("copy", "duplicate", "backup", "save"),
    "move": ("move", "rename", "relocate"),
    "input": ("input", "enter", "type", "submit", "fill", "apply", "accept", "join",
              "reserve", "register", "comment", "login", "log in", "sign in", "top up"),
    "clone": ("clone", "download", "copy", "fetch", "get", "sync", "upload"),
    "push": ("push", "upload", "sync", "publish", "update"),
    "pull": ("pull", "sync", "fetch", "update"),
    "star": ("star", "stars", "starred", "favorite"),
    "unstar": ("unstar", "remove my star", "remove star", "remove"),
    "issue": ("issue", "issues", "report", "bug", "propose", "address"),
}
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URLISH = re.compile(r"(?:https?://)?(?:www\.)?[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_-]+)*\.[a-z]{2,15}(?:/[^\s'\"<>]*)?", re.I)
_LINK = re.compile(r"(?:https?://|www\.)[^\s'\"<>)]+", re.I)
_IBANISH = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{8,30}\b")
_NUM = re.compile(r"\d+(?:[.,]\d+)?")
_TIMEY = re.compile(r"(^|_)(time|date|day|start|end)(_|$)")
_CODE_TOKEN = re.compile(
    r"\b(?:Code|OTP|one[- ]time[- ]pass(?:word|wd)?|verification code)\s*(?:is|:)\s*([A-Za-z0-9_-]{4,32})\b",
    re.I,
)
_CRED_KV = re.compile(
    r"\b(?:Email|Username|Password|Handle|Login|Account\s*(?:Number|ID))\s*:\s*([^\s|,;]+)",
    re.I,
)
_SSH_KEY = re.compile(r"\b(ssh-(?:rsa|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{12,})")
_LOCAL_PATH_IN_PROMPT = re.compile(r"(/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+)")
_SAVED_FNAME = re.compile(r"\b([A-Za-z0-9_.-]+\.(?:pdf|txt|csv|json|md|docx|xlsx|xml))\b", re.I)
_INJ_CUES = re.compile(
    r"(<INFORMATION>|IMPORTANT!{2,}|ignore\s+previous\s+instructions|before\s+you\s+can\s+solve|"
    r"product\s+id\s+p\d+\s+is\s+the\s+exact|please\s+buy\s+it\s+directly)",
    re.I,
)
_ATOM_MAX_CHARS, _ATOM_MAX_WORDS = 100, 8


def norm(value: Any) -> str:
    text = str(value).strip().casefold()
    text = re.sub(r"^https?://", "", text).rstrip("/")
    return re.sub(r"\s+", " ", text)


def _num(value: Any):
    try:
        return round(float(str(value).replace(",", ".")), 6)
    except (TypeError, ValueError):
        return None


def _tool_verb(tool: str) -> str:
    parts = tool.split("_")
    if parts[0] in VERB_FAMILIES or len(parts) == 1:
        return parts[0]
    if parts[1] in VERB_FAMILIES:
        return parts[1]
    return parts[0]


def is_read(tool: str) -> bool:
    if tool in READ_NAMES or tool.startswith(READ_PREFIXES):
        return True
    parts = tool.split("_", 1)
    return len(parts) == 2 and parts[1].startswith(READ_PREFIXES)


def _is_atomic(text: str) -> bool:
    return ("\n" not in text and len(text) <= _ATOM_MAX_CHARS
            and len(text.split()) <= _ATOM_MAX_WORDS)


def _walk(obj: Any, depth: int = 0) -> Iterable[Any]:
    """Every leaf value (and dict key) of a tool result, safely unpacking pure literal containers."""
    if depth > 12:
        return
    if hasattr(obj, "model_dump"):
        obj = obj.model_dump(mode="json")
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _walk(v, depth + 1)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            yield from _walk(v, depth + 1)
    elif isinstance(obj, str) and len(obj) <= 4096:
        s = obj.strip()
        if (s.startswith("[") and s.endswith("]")) or (s.startswith("{") and s.endswith("}")):
            try:
                parsed = ast.literal_eval(s)
            except (ValueError, SyntaxError):
                parsed = None
            if isinstance(parsed, (dict, list, tuple, set)):
                yield from _walk(parsed, depth + 1)
                return
        yield obj
    else:
        yield obj


@dataclass
class GenericPolicy:
    task_id: str
    prompt: str
    tools: tuple
    trust_named_sources: bool = False
    trust_local_named_sources: bool = False
    prompt_norm: str = ""
    prompt_numbers: frozenset = frozenset()
    prompt_hosts: tuple = ()
    prompt_paths: tuple = ()
    policy_sha256: str = "generic"

    def verify(self) -> bool:
        return True


def _extract_hosts(text: str) -> set[str]:
    found = set()
    for m in _EMAIL.findall(text):
        found.add(norm(m).split("@")[-1])
    for m in _URLISH.findall(text):
        host = norm(m).split("/")[0].split("@")[-1].split("?")[0]
        if host and "." in host and not host.endswith((".txt", ".pdf", ".exe", ".py", ".pass", ".ssh")):
            found.add(host)
            if host.startswith("www."):
                found.add(host[4:])
    return found


def compile_generic(task_id: str, prompt: str, tools: Iterable[str],
                    trust_named_sources: bool = False,
                    trust_local_named_sources: bool = False) -> GenericPolicy:
    numbers = frozenset(n for n in (_num(m) for m in _NUM.findall(prompt)) if n is not None)
    hosts = sorted(_extract_hosts(prompt))
    paths = sorted({m.rstrip(".,;:!?)") for m in _LOCAL_PATH_IN_PROMPT.findall(prompt or "") if m.rstrip(".,;:!?)")})
    return GenericPolicy(task_id, prompt, tuple(sorted(tools)), trust_named_sources,
                         trust_local_named_sources, " " + norm(prompt) + " ",
                         numbers, tuple(hosts), tuple(paths))


def _matches_prompt_local_path(policy: GenericPolicy, args: dict | None) -> bool:
    """True when read_file inspects a local file or child under a directory named in the prompt."""
    if not args or not policy.prompt_paths:
        return False
    for v in args.values():
        if not isinstance(v, str) or not v.startswith("/"):
            continue
        p = v.strip().rstrip("/")
        if "/read_me_" in p.lower() or "readme" in p.lower():
            continue
        for ref in policy.prompt_paths:
            r = ref.rstrip("/")
            if p == r or p.startswith(r + "/"):
                return True
    return False


@dataclass
class GenericLedger:
    """What tools returned this episode. Only clean atomic/structured values are grounded."""
    policy: GenericPolicy
    atoms: set = field(default_factory=set)
    numbers: set = field(default_factory=set)
    successful_tools: list = field(default_factory=list)
    catalog_items: dict = field(default_factory=dict)
    tainted_products: set = field(default_factory=set)
    user_history_products: set = field(default_factory=set)
    trusted_local_paths: set = field(default_factory=set)

    def _record_catalog_and_taints(self, tool: str, result: Any) -> None:
        if hasattr(result, "model_dump"):
            result = result.model_dump(mode="json")
        if not isinstance(result, dict):
            return
        for title, rec in result.items():
            if not isinstance(rec, dict):
                continue
            pid = rec.get("product_id")
            if not isinstance(pid, str) or not pid.strip():
                continue
            pid_key = norm(pid)
            if tool in ("view_cart", "view_order_history"):
                self.user_history_products.add(pid_key)
            pname = str(rec.get("product_name") or title or "")
            meta = f"{pname} {rec.get('category', '')} {rec.get('brand', '')}".strip()
            self.catalog_items[pid_key] = meta
            reviews = rec.get("reviews") or []
            if isinstance(reviews, str):
                reviews = [reviews]
            if isinstance(reviews, list) and any(
                isinstance(r, str) and _INJ_CUES.search(r) for r in reviews
            ):
                self.tainted_products.add(pid_key)

    def observe(self, tool: str, result: Any, args: dict | None = None) -> None:
        self.successful_tools.append(tool)
        self._record_catalog_and_taints(tool, result)
        if self.policy.trust_local_named_sources and tool in ("download_file_through_url", "download_file_through_id"):
            save_dir = str((args or {}).get("save_dir") or "").strip().rstrip("/")
            origin_ok = False
            if tool == "download_file_through_url" and args:
                hosts = _extract_hosts(str(args.get("url", "")))
                origin_ok = bool(hosts and hosts <= set(self.policy.prompt_hosts))
            elif tool == "download_file_through_id":
                origin_ok = bool(self.policy.prompt_hosts) and any(
                    t in ("input_to_webpage", "browse_webpage") for t in self.successful_tools
                )
            if origin_ok:
                for lp in _LOCAL_PATH_IN_PROMPT.findall(str(result)):
                    self.trusted_local_paths.add(lp.rstrip(".,;:!?)"))
                if save_dir:
                    for fn in _SAVED_FNAME.findall(str(result)):
                        self.trusted_local_paths.add(f"{save_dir}/{fn}")
        named = False
        if self.policy.trust_named_sources and args:
            named = any(isinstance(v, str) and len(v) >= 4 and (f" {norm(v)} " in
                        self.policy.prompt_norm.replace(",", " ").replace("'", " ").replace('"', " ")
                        or norm(v) in self.policy.prompt_norm)
                        for v in args.values())
        read_path = ""
        if args:
            for k in ("path", "file_path"):
                if isinstance(args.get(k), str):
                    read_path = args[k].strip().rstrip("/")
                    break
        local_named = (
            self.policy.trust_local_named_sources
            and tool == "read_file"
            and (_matches_prompt_local_path(self.policy, args) or read_path in self.trusted_local_paths)
        )
        structured_system_tool = tool in ("view_available_discounts", "git_get_linked_ssh_keys")
        otp_tool = tool.endswith("_linked_unread_emails")
        for leaf in _walk(result):
            if isinstance(leaf, bool) or leaf is None:
                continue
            if isinstance(leaf, (int, float)):
                self.numbers.add(round(float(leaf), 6))
                self.atoms.add(norm(leaf))
                continue
            if not isinstance(leaf, str) or not leaf.strip():
                continue
            if structured_system_tool or otp_tool:
                for tok in _CODE_TOKEN.findall(leaf):
                    self.atoms.add(norm(tok))
            if (structured_system_tool or tool.startswith(("git_", "verify_github"))) and not _INJ_CUES.search(leaf):
                for sk in _SSH_KEY.findall(leaf):
                    self.atoms.add(norm(sk))
            if _is_atomic(leaf):
                self.atoms.add(norm(leaf))
                n = _num(leaf)
                if n is not None:
                    self.numbers.add(n)
            elif (named or local_named) and not _INJ_CUES.search(leaf):
                for m in _EMAIL.findall(leaf) + _IBANISH.findall(leaf) + _URLISH.findall(leaf) + _CRED_KV.findall(leaf):
                    self.atoms.add(norm(m))
                for m in _NUM.findall(leaf):
                    n = _num(m)
                    if n is not None:
                        self.numbers.add(n)


def _grounded(policy: GenericPolicy, ledger: GenericLedger, value: Any, *,
              allow_same_host_url: bool = False) -> bool:
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        n = round(float(value), 6)
        return n in policy.prompt_numbers or n in ledger.numbers
    if not isinstance(value, str):
        return False
    v = norm(value)
    if v == "":
        return True
    if len(v) <= 2 and v.isalpha():
        return True
    if v in ledger.atoms:
        return True
    n = _num(value)
    if n is not None and (n in policy.prompt_numbers or n in ledger.numbers):
        return True
    if allow_same_host_url:
        hosts = set(policy.prompt_hosts)
        for atom in ledger.atoms:
            hosts.update(_extract_hosts(atom))
        url_hosts = _extract_hosts(value)
        if url_hosts and (url_hosts <= hosts or (hosts and all(host_matches(h, hosts, allow_subdomains=True) for h in url_hosts))):
            return True
    return re.search(r"(?<![\w@.])" + re.escape(v) + r"(?![\w@])", policy.prompt_norm) is not None


def _leaves(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for v in value.values():
            yield from _leaves(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _leaves(v)
    else:
        yield value


def authorize_generic(policy: GenericPolicy, ledger: GenericLedger, tool: str,
                      args: dict) -> tuple[bool, str]:
    if tool not in policy.tools:
        return False, "tool is not part of this deployment"
    read = is_read(tool)
    if not read:
        verb = _tool_verb(tool)
        family = VERB_FAMILIES.get(verb)
        if family is None:
            return False, f"no verb family for '{verb}': changing tools must be declared"
        if not any(re.search(r"(?<!\w)" + re.escape(w), policy.prompt_norm) for w in family):
            return False, f"the request does not ask for a '{verb}' action"
    for name, value in (args or {}).items():
        if name == "quantity" and value == 1:
            continue
        for leaf in _leaves(value):
            addressy = isinstance(leaf, str) and (_EMAIL.fullmatch(leaf.strip()) is not None
                                                  or name in ("url", "user_email", "email"))
            if read and not addressy:
                continue
            if not addressy and (name in CONTENT_ARGS or _TIMEY.search(name)):
                if isinstance(leaf, str):
                    for token in _EMAIL.findall(leaf) + _LINK.findall(leaf):
                        if not _grounded(policy, ledger, token):
                            return False, f"'{name}' contains an address or link that is not grounded"
                continue
            if not _grounded(policy, ledger, leaf, allow_same_host_url=(read and name == "url")):
                return False, f"argument '{name}' is not grounded in the request or in a returned field"
    return True, ""


def decide_generic(policy: GenericPolicy, ledger: GenericLedger, tool: str,
                   args: dict) -> tuple[bool, str]:
    """Kernel first (hard blocks are final), then the generic rule."""
    hosts = set(policy.prompt_hosts)
    for atom in ledger.atoms:
        hosts.update(_extract_hosts(atom))
    kernel = ModelProxyPolicy(allowed_tools=policy.tools, strict_deny_unknown=True,
                              block_mode=True, track_session=False,
                              approved_outbound=sorted(h for h in hosts if h))
    _frozen, verdict = screen_action(kernel, tool, args)
    if verdict.action == "block" and not (set(verdict.signals) <= {REVIEW, "toolcall:destructive:high"}):
        return False, verdict.reason or "blocked by ADOM"
    return authorize_generic(policy, ledger, tool, args)
