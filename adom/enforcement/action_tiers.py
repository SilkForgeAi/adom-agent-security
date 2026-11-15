"""Action tiers: give any agent action a deterministic default before it runs.

ADOM's kernel denies any tool without an exact grant (Oct 11 hardening). That is right for
security, but it means every tool ADOM has never seen is blocked until someone writes a
policy for it. This module is the layer in between. It sorts each action by what it can do:

  observe        reads local state only                     (Read, Grep, Glob, read_file)
  local_write    changes local state                        (Write, Edit, delete_file)
  consequential  leaves the machine or acts for the user    (WebFetch, send_email, http_post)
  unknown        not classified by anything trusted

Where a tier comes from, in order of trust:
  1. the built-in table for the agent adapter (tools shipped by the agent vendor)
  2. the operator registry, ~/.adom/tool_tiers.json, written by a person (the agent may not
     write it: ~/.adom is self-protected by the coding-agent hook)
  3. nothing -> unknown

Rules that never bend:
  * Tool self-descriptions (MCP readOnlyHint / destructiveHint / openWorldHint) can only
    RAISE a tier, never lower it. A tool cannot talk its way into "observe".
  * The operator registry can tighten a built-in tool, never loosen it.
  * Unknown MCP tools are denied. A name-based guess is recorded as `proposed` so a person
    can review it, but the guess is never execution authority.
  * Reading or writing credential stores, and writing persistence locations (shell rc files,
    ~/.ssh, LaunchAgents), is denied at any tier: in a coding agent a read sends the file
    into the model's context, which is egress to the model provider.
  * A tier only decides what grant ADOM's kernel receives. A registry-granted tool is still
    screened by adom.enforcement.action_kernel.screen_action; a kernel block always wins.

Text matching on paths is deterministic but bounded: it catches direct and symlinked paths,
globs and $HOME forms, not a determined adversary who builds a path at run time. That limit
is stated in spec/action_tiers.md.

Python 3.9 compatible (macOS system python). No model, no network.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

OBSERVE, LOCAL_WRITE, CONSEQUENTIAL, UNKNOWN = "observe", "local_write", "consequential", "unknown"
TIERS = (OBSERVE, LOCAL_WRITE, CONSEQUENTIAL, UNKNOWN)
_RANK = {t: i for i, t in enumerate(TIERS)}

REGISTRY_PATH = Path.home() / ".adom" / "tool_tiers.json"

# --------------------------------------------------------------------------- built-ins
# Tools shipped by the agent vendor and run under the agent's own permission system.
# Names are matched case-insensitively. Shell is handled by the shell hook, not here.
BUILTIN: Dict[str, Dict[str, str]] = {
    "claude_code": {
        "read": OBSERVE, "grep": OBSERVE, "glob": OBSERVE, "ls": OBSERVE,
        "notebookread": OBSERVE, "todowrite": OBSERVE, "todoread": OBSERVE,
        "bashoutput": OBSERVE, "exitplanmode": OBSERVE,
        # Task starts a subagent; each of its tool calls goes through these hooks again.
        "task": OBSERVE,
        "write": LOCAL_WRITE, "edit": LOCAL_WRITE, "multiedit": LOCAL_WRITE,
        "notebookedit": LOCAL_WRITE, "killshell": LOCAL_WRITE,
        "webfetch": CONSEQUENTIAL, "websearch": CONSEQUENTIAL,
    },
    "cursor": {
        "read_file": OBSERVE, "read": OBSERVE, "grep": OBSERVE, "glob": OBSERVE,
        "ls": OBSERVE, "list": OBSERVE, "list_dir": OBSERVE, "search": OBSERVE,
        "codebase_search": OBSERVE, "semanticsearch": OBSERVE, "filesearch": OBSERVE,
        "file_search": OBSERVE, "grep_search": OBSERVE, "task": OBSERVE,
        "todo_write": OBSERVE, "read_lints": OBSERVE,
        "write": LOCAL_WRITE, "edit": LOCAL_WRITE, "multiedit": LOCAL_WRITE,
        "edit_file": LOCAL_WRITE, "write_file": LOCAL_WRITE, "search_replace": LOCAL_WRITE,
        "apply_patch": LOCAL_WRITE, "delete": LOCAL_WRITE, "delete_file": LOCAL_WRITE,
        "edit_notebook": LOCAL_WRITE,
        "web_search": CONSEQUENTIAL, "fetch": CONSEQUENTIAL, "webfetch": CONSEQUENTIAL,
    },
}
# The read event both adapters translate file reads into.
BUILTIN["claude_code"]["read_file"] = OBSERVE

_PATH_KEYS = ("file_path", "path", "target_file", "notebook_path", "target_notebook",
              "directory", "dir", "filename")

# --------------------------------------------------------------------------- sensitive paths
# Matched against lower-cased, '/'-separated, ~-expanded text, both as given and with
# symlinks resolved. Home-agnostic: '/.ssh/' anywhere, any user.
_SSH_OK = re.compile(r"/\.ssh/(config|known_hosts(\.old)?|authorized_keys|[^/]*\.pub)$")
_CREDENTIAL_RX: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(_sk)?$"), "ssh_private_key"),
    (re.compile(r"/\.ssh/[^/]+$"), "ssh_directory_file"),
    (re.compile(r"/\.aws/(credentials|sso/cache/.*|cli/cache/.*)$"), "aws_credentials"),
    (re.compile(r"/\.config/gcloud/(credentials\.db|access_tokens\.db|"
                r"application_default_credentials\.json|legacy_credentials/.*)$"), "gcloud_credentials"),
    (re.compile(r"/\.azure/(accesstokens\.json|msal_token_cache.*)$"), "azure_credentials"),
    (re.compile(r"/\.kube/config$"), "kubeconfig"),
    (re.compile(r"/\.docker/config\.json$"), "docker_auth"),
    (re.compile(r"/\.config/gh/hosts\.ya?ml$"), "github_cli_token"),
    (re.compile(r"(^|/)\.(netrc|git-credentials|pypirc)$"), "credential_file"),
    (re.compile(r"/library/keychains/.*"), "macos_keychain"),
    (re.compile(r"/\.gnupg/(private-keys-v1\.d/.*|secring\.gpg)$"), "gpg_private_key"),
    (re.compile(r"/\.password-store/.*"), "password_store"),
    # ADOM's own keys (approval and audit): an agent that reads one can mint approvals.
    (re.compile(r"/\.adom/(.*/)?[^/]*\.key$"), "adom_key"),
]
# Writing here gives an agent persistence beyond the session or rewrites who can log in.
_PERSISTENCE_RX: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(^|/)\.(bashrc|bash_profile|bash_login|profile|zshrc|zprofile|zshenv|"
                r"zlogin|cshrc|tcshrc)$"), "shell_startup_file"),
    (re.compile(r"/\.config/fish/config\.fish$"), "shell_startup_file"),
    (re.compile(r"/\.ssh/"), "ssh_configuration"),
    (re.compile(r"/library/launch(agents|daemons)/"), "launch_agent"),
    (re.compile(r"/\.config/autostart/"), "autostart"),
    (re.compile(r"^/etc/"), "system_config"),
    (re.compile(r"/\.git/hooks/"), "git_hook"),
]
# Directories whose recursive search would return credential contents (Grep over ~/.ssh).
_CRED_DIR_RX = re.compile(r"/\.(ssh|aws|gnupg|kube|docker|azure|password-store|adom)/?$|"
                          r"/\.config/(gcloud|gh)/?$|/library/keychains/?$")
_RECURSIVE_READ_TOOLS = {"grep", "grep_search", "search", "codebase_search"}
_DOTENV_RX = re.compile(r"(^|/)\.env(\.[^/]*)?$")
_DOTENV_SAFE_RX = re.compile(r"(^|/)\.env\.(example|sample|template|dist|schema)$", re.I)
_SHELL_DOTENV_RX = re.compile(r"(?:^|[\s'\"=/@])\.env(?:\.(?!example\b|sample\b|template\b|dist\b|schema\b)[a-z0-9_.-]+)?(?=$|[\s'\"|;&<>])", re.I)

# Shell text markers for the same credential stores (globs and $HOME forms included).
_SHELL_CRED_RX = re.compile(
    r"\.ssh/(?!(config|known_hosts|authorized_keys)\b)(?![^\s'\"|;&<>]*\.pub\b)[^\s'\"|;&<>]+"
    r"|\bid_(rsa|dsa|ecdsa|ed25519)(?!\.pub)\b|\bid_[*?\[]"
    r"|\.aws/(credentials|sso/cache|cli/cache)"
    r"|\.config/gcloud/(credentials|access_tokens|application_default|legacy_credentials)"
    r"|\.kube/config\b|\.docker/config\.json|\.config/gh/hosts"
    r"|\.(netrc|git-credentials|pypirc)\b|library/keychains|\.gnupg/private-keys"
    r"|\bsecurity\s+(find-generic-password|find-internet-password|dump-keychain)\b")
# Programs that USE a key file locally. scp/rsync/sftp are excluded: they can copy it away.
_SHELL_KEY_TOOLS = {"ssh", "ssh-add", "ssh-keygen", "ssh-copy-id", "git"}
_SHELL_META = re.compile(r"[|;&<>`]|\$\(")
# A credential DIRECTORY named in a command that also runs something able to read or ship
# file contents (cd ~/.ssh; cat *   /   grep -r BEGIN ~/.ssh   /   cat ~/.aws/cred*).
_SHELL_CRED_DIR = re.compile(r"\.(ssh|aws|gnupg|kube|docker|azure|password-store)\b(/[^\s'\"|;&<>]*)?")
_SHELL_DIR_OK_TAIL = re.compile(r"^/(config|known_hosts|authorized_keys|[^/\s]*\.pub)$")
_SHELL_READERS = re.compile(r"(?<![\w.-])(cat|less|more|head|tail|bat|grep|egrep|rg|ag|awk|sed|tar|zip|"
                            r"gzip|cp|mv|scp|rsync|sftp|curl|wget|nc|ncat|socat|base64|xxd|od|"
                            r"hexdump|strings|python3?|node|perl|ruby|php|find|xargs|tee|dd|"
                            r"openssl|gpg|pbcopy|osascript)(?![\w.-])")


def _norm(p: str) -> str:
    p = str(p or "").strip().replace("\\", "/")
    for var in ("${HOME}", "$HOME"):
        if p == var or p.startswith(var + "/"):
            p = str(Path.home()) + p[len(var):]
            break
    return os.path.expanduser(p)


def _forms(path: str, cwd: str = "") -> List[str]:
    p = _norm(path)
    if not p:
        return []
    if not os.path.isabs(p) and cwd:
        p = os.path.join(cwd, p)
    out = [p.lower()]
    try:
        r = os.path.realpath(p).lower()
        if r not in out:
            out.append(r)
    except (OSError, ValueError):
        pass
    return out


def _credential_inodes() -> set:
    """(dev, ino) of credential files in this user's home, to catch hard links."""
    found = set()
    home = Path.home()
    cands = [home / ".aws" / "credentials", home / ".netrc", home / ".git-credentials",
             home / ".kube" / "config", home / ".docker" / "config.json"]
    try:
        cands += [p for p in (home / ".ssh").iterdir() if p.is_file()]
    except OSError:
        pass
    for p in cands:
        try:
            if not _SSH_OK.search(str(p).lower()):
                st = p.stat()
                found.add((st.st_dev, st.st_ino))
        except OSError:
            pass
    return found


def credential_label(path: str, cwd: str = "") -> Optional[str]:
    forms = _forms(path, cwd)
    for f in forms:
        if _SSH_OK.search(f):
            continue
        for rx, label in _CREDENTIAL_RX:
            if rx.search(f):
                return label
    if forms:                                         # a hard link carries no path clue
        try:
            st = os.stat(forms[-1])
            if st.st_nlink > 1 and (st.st_dev, st.st_ino) in _credential_inodes():
                return "hard_link_to_credential"
        except (OSError, ValueError):
            pass
    return None


def credential_dir_label(path: str, cwd: str = "") -> Optional[str]:
    for f in _forms(path, cwd):
        if _CRED_DIR_RX.search(f):
            return "credential_directory"
    return None


def persistence_label(path: str, cwd: str = "") -> Optional[str]:
    for f in _forms(path, cwd):
        for rx, label in _PERSISTENCE_RX:
            if rx.search(f):
                return label
    return None


def shell_credential_access(command: str) -> Optional[str]:
    """Credential store named in a shell command, unless the command only hands a key to
    a program that uses it (ssh -i, git, ssh-add) with no pipe, redirect or substitution."""
    cmd = str(command or "")
    # Dequote trivial shell obfuscation (e.g. ~/.s'sh'/id_rsa or .e''nv) before matching.
    dequoted = re.sub(r"['\"\\]", "", cmd)
    low = dequoted.lower()
    m = _SHELL_CRED_RX.search(low)
    if not m:
        for dm in _SHELL_CRED_DIR.finditer(low):
            tail = dm.group(2) or ""
            if tail and _SHELL_DIR_OK_TAIL.match(tail):
                continue
            if dm.group(1) == "aws" and tail == "/config":
                continue
            if _SHELL_READERS.search(low):
                return dm.group(0)
        em = _SHELL_DOTENV_RX.search(low)
        if em and _SHELL_READERS.search(low):
            return ".env"
        return None
    first = dequoted.strip().split()[0].rsplit("/", 1)[-1] if dequoted.strip() else ""
    if first in _SHELL_KEY_TOOLS and not _SHELL_META.search(cmd):
        return None
    return m.group(0)


# --------------------------------------------------------------------------- secrets in args
def _secret_rx():
    try:
        from adom.enforcement.egress_proxy import _SECRET_RX
    except Exception:                                  # pragma: no cover - import guard
        return []
    return [(re.compile(r"(?<![A-Za-z0-9_\-])(?:" + rx.pattern + ")", rx.flags), label)
            for rx, label in _SECRET_RX if label != "credential_kv"]


_SECRETS = None


def secret_labels(values: Iterable[str]) -> List[str]:
    global _SECRETS
    if _SECRETS is None:
        _SECRETS = _secret_rx()
    found = set()
    for v in values:
        for rx, label in _SECRETS:
            if rx.search(v):
                found.add(label)
    return sorted(found)


def strings(obj: Any, out: Optional[List[str]] = None, depth: int = 0) -> List[str]:
    out = [] if out is None else out
    if depth > 20 or len(out) > 4000:
        return out
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            strings(k, out, depth + 1)
            strings(v, out, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            strings(v, out, depth + 1)
    return out


_PATHLIKE = re.compile(r"^(file://|~|\$\{?home\}?/|/|\.{1,2}/)[^\s]*$", re.I)


def paths_in(args: Any, everywhere: bool = False) -> List[str]:
    """Path arguments. Built-in tools: the known path keys only (so an edit whose CONTENT
    mentions ~/.ssh is not mistaken for touching it). Third-party tools (everywhere=True):
    also any string argument that is itself a single path or file:// URI."""
    out: List[str] = []
    if isinstance(args, dict):
        out = [str(args[k]) for k in _PATH_KEYS if isinstance(args.get(k), str) and args.get(k)]
    if everywhere:
        for v in strings(args):
            if len(v) < 1024 and _PATHLIKE.match(v.strip()):
                v = v.strip()
                out.append(v[7:] if v.lower().startswith("file://") else v)
    return list(dict.fromkeys(out))


# --------------------------------------------------------------------------- registry
@dataclass(frozen=True)
class RegistryEntry:
    tier: str
    approved_outbound: Tuple[str, ...] = ()
    note: str = ""
    # Opt-in, per tool: the kernel's "review required" verdict for outbound to an approved
    # destination may be satisfied by the agent's own approval prompt. Hard kernel blocks
    # (unapproved destination, secrets, taint) are never affected. Off by default.
    agent_approval: bool = False


@dataclass
class Registry:
    tools: Dict[str, RegistryEntry] = field(default_factory=dict)
    error: str = ""                                   # non-empty -> treated as empty (fail closed)
    path: str = ""


def load_registry(path: Optional[Path] = None) -> Registry:
    path = Path(path) if path else REGISTRY_PATH
    if not path.exists():
        return Registry(path=str(path))
    try:
        raw = json.loads(path.read_text())
        if not isinstance(raw, dict) or raw.get("version") != 1 or not isinstance(raw.get("tools"), dict):
            raise ValueError("expected {\"version\": 1, \"tools\": {...}}")
        tools = {}
        for name, e in raw["tools"].items():
            if not isinstance(e, dict) or e.get("tier") not in (OBSERVE, LOCAL_WRITE, CONSEQUENTIAL):
                raise ValueError(f"entry {name!r}: tier must be observe, local_write or consequential")
            out = e.get("approved_outbound", [])
            if not isinstance(out, list) or not all(isinstance(x, str) and x for x in out):
                raise ValueError(f"entry {name!r}: approved_outbound must be a list of hosts")
            aa = e.get("agent_approval", False)
            if not isinstance(aa, bool):
                raise ValueError(f"entry {name!r}: agent_approval must be true or false")
            if aa and (e["tier"] != CONSEQUENTIAL or not out):
                raise ValueError(f"entry {name!r}: agent_approval needs tier consequential "
                                 f"and a non-empty approved_outbound")
            tools[str(name)] = RegistryEntry(e["tier"], tuple(out), str(e.get("note", "")), aa)
        return Registry(tools=tools, path=str(path))
    except (OSError, ValueError) as exc:
        return Registry(error=f"{type(exc).__name__}: {exc}", path=str(path))


# --------------------------------------------------------------------------- proposals
_VERB_CONSEQUENTIAL = re.compile(
    r"(send|post|email|mail|message|publish|push|deploy|pay|transfer|invite|share|upload|"
    r"webhook|http|request|fetch|browse|navigate|tweet|notify|sms|call|merge|release|"
    r"execute|exec|run|eval|shell|command|install)")
_VERB_WRITE = re.compile(r"(create|update|write|edit|set|add|insert|delete|remove|move|"
                         r"rename|patch|put|save|store|append|drop|clear|reset|upsert|modify)")
_VERB_READ = re.compile(r"(^|[_\-:.])(get|list|read|search|query|describe|view|show|find|"
                        r"lookup|count|stat|status|info|inspect|retrieve)([_\-]|$)")


def propose_tier(name: str) -> str:
    """A reviewable GUESS from the tool name. Never execution authority: a malicious server
    can name a write tool 'get_notes'. Ambiguous names propose consequential."""
    n = str(name or "").lower()
    if _VERB_CONSEQUENTIAL.search(n):
        return CONSEQUENTIAL
    if _VERB_WRITE.search(n):
        return LOCAL_WRITE
    if _VERB_READ.search(n):
        return OBSERVE
    return CONSEQUENTIAL


# --------------------------------------------------------------------------- classify
@dataclass(frozen=True)
class Classification:
    tool: str
    tier: str
    source: str                         # builtin:<agent> | registry | none
    reasons: Tuple[str, ...] = ()
    sensitive: Tuple[str, ...] = ()     # credential:<label> | persistence:<label> | dotenv
    secrets: Tuple[str, ...] = ()       # credential-shaped values in the arguments
    proposed: Optional[str] = None      # for unknown tools only
    registry_entry: Optional[RegistryEntry] = None
    registry_error: str = ""

    def as_log(self) -> Dict[str, Any]:
        d = {"tier": self.tier, "tier_source": self.source}
        if self.reasons:
            d["tier_reasons"] = list(self.reasons)
        if self.sensitive:
            d["sensitive"] = list(self.sensitive)
        if self.secrets:
            d["arg_secrets"] = list(self.secrets)
        if self.proposed:
            d["proposed_tier"] = self.proposed
        if self.registry_error:
            d["registry_error"] = self.registry_error
        return d


def _raise_to(tier: str, floor: str) -> str:
    return tier if _RANK[tier] >= _RANK[floor] else floor


def is_mcp(name: str) -> bool:
    n = str(name or "")
    return n.startswith("mcp:") or n.startswith("mcp__")


def classify(name: str, args: Any = None, agent: str = "cursor", cwd: str = "",
             hints: Optional[Dict[str, Any]] = None,
             registry: Optional[Registry] = None) -> Classification:
    name = str(name or "")
    registry = registry if registry is not None else load_registry()
    reasons: List[str] = []
    entry = None
    builtin = None if is_mcp(name) else BUILTIN.get(agent, {}).get(name.lower())
    if builtin:
        tier, source = builtin, f"builtin:{agent}"
        reg = registry.tools.get(name)
        if reg and _RANK[reg.tier] > _RANK[tier]:
            tier, entry = reg.tier, reg
            reasons.append("registry tightened a built-in tool")
    elif name in registry.tools:
        entry = registry.tools[name]
        tier, source = entry.tier, "registry"
    else:
        tier, source = UNKNOWN, "none"
    if hints and tier != UNKNOWN:                       # hints only ever raise
        if hints.get("openWorldHint") is True:
            new = _raise_to(tier, CONSEQUENTIAL)
            if new != tier:
                reasons.append("tool declares openWorldHint")
            tier = new
        if hints.get("destructiveHint") is True:
            new = _raise_to(tier, LOCAL_WRITE)
            if new != tier:
                reasons.append("tool declares destructiveHint")
            tier = new
    sensitive: List[str] = []
    for p in paths_in(args, everywhere=not builtin):
        c = credential_label(p, cwd)
        if c:
            sensitive.append("credential:" + c)
        if tier != OBSERVE and not c:
            pl = persistence_label(p, cwd)
            if pl:
                sensitive.append("persistence:" + pl)
        if name.lower() in _RECURSIVE_READ_TOOLS and not c:
            d = credential_dir_label(p, cwd)
            if d:
                sensitive.append("credential:" + d)
        if any(_DOTENV_RX.search(f) and not _DOTENV_SAFE_RX.search(f) for f in _forms(p, cwd)):
            sensitive.append("dotenv")
    secrets: Tuple[str, ...] = ()
    if tier in (CONSEQUENTIAL, UNKNOWN):               # values that would leave the machine
        secrets = tuple(secret_labels(strings(args)))
    return Classification(
        tool=name, tier=tier, source=source, reasons=tuple(reasons),
        sensitive=tuple(dict.fromkeys(sensitive)), secrets=secrets,
        proposed=propose_tier(name) if tier == UNKNOWN else None,
        registry_entry=entry, registry_error=registry.error)


# --------------------------------------------------------------------------- decide
ALLOW, DEFER, SCREEN, BLOCK = "allow", "defer", "screen", "block"


@dataclass(frozen=True)
class TierDecision:
    action: str          # allow | defer | screen | block
    reason: str
    signals: Tuple[str, ...]


def decide(c: Classification) -> TierDecision:
    """Coding-agent posture.

    allow  -> no objection from the tier layer (other ADOM checks still apply)
    defer  -> no objection; the agent's own approval prompt governs (vendor built-ins)
    screen -> run ADOM's kernel with an exact grant for this one tool; kernel decides
    block  -> deny
    """
    cred = [s for s in c.sensitive if s.startswith("credential:")]
    if cred:
        return TierDecision(BLOCK, f"credential containment: '{c.tool}' would touch a credential "
                                   f"store ({cred[0].split(':', 1)[1]})",
                            ("tier:credential_store",))
    pers = [s for s in c.sensitive if s.startswith("persistence:")]
    if pers:
        return TierDecision(BLOCK, f"'{c.tool}' would write a persistence location "
                                   f"({pers[0].split(':', 1)[1]})", ("tier:persistence_write",))
    if "dotenv" in c.sensitive and c.tier != LOCAL_WRITE:
        return TierDecision(BLOCK, f"credential containment: '{c.tool}' would access a .env file",
                            ("tier:credential_store", "tier:dotenv"))
    if c.secrets:
        return TierDecision(BLOCK, f"'{c.tool}' would send a credential-shaped value off the "
                                   f"machine ({', '.join(c.secrets)})", ("tier:secret_in_outbound_args",))
    if c.tier == UNKNOWN:
        if is_mcp(c.tool):
            why = f"registry unreadable ({c.registry_error}); " if c.registry_error else ""
            return TierDecision(BLOCK, f"{why}unclassified MCP tool '{c.tool}' - unknown tools are "
                                       f"denied; proposed tier '{c.proposed}' needs a person to approve "
                                       f"it in ~/.adom/tool_tiers.json", ("tier:unknown_denied",))
        return TierDecision(DEFER, "unclassified vendor tool; agent approval governs",
                            ("tier:unknown_builtin_deferred",))
    if c.source == "registry" or c.registry_entry is not None:
        return TierDecision(SCREEN, "", (f"tier:{c.tier}", "tier:kernel_screen"))
    if c.tier == CONSEQUENTIAL:
        return TierDecision(DEFER, "", ("tier:consequential", "tier:agent_approval"))
    return TierDecision(ALLOW, "", (f"tier:{c.tier}",))


_REVIEW = "action_kernel:review_required"
_HARD = ("strict_egress", "exfil", "taint", "fail_closed", "secret")


def screen(c: Classification, args: Any,
           prompt_confirmed: Tuple[bool, str] = (False, "approval prompt not checked"),
           contracts: Any = None, approvals: Any = None, agent_id: str = "agent") -> TierDecision:
    """Run ADOM's kernel for one registry-granted tool, with an exact grant for it only.

    The kernel's verdict stands, with one opt-in exception: if the registry entry sets
    agent_approval, and the kernel's only objection is "review required" (a flag, which the
    kernel never treats as permission), AND the adapter has confirmed from the agent's own
    settings that a person will see the approval prompt (prompt_confirmed), the decision is
    DEFER: that prompt is the review. Any hard kernel signal still blocks.

    contracts / approvals (enforcement.review): a declared contract can refuse the call or
    require review; an exact approval on file releases a review-required verdict. A review
    that a CONTRACT demands is never handed to the agent's own prompt."""
    from adom.api.model_proxy import ModelProxyPolicy, ProxyVerdict
    from adom.enforcement.action_kernel import screen_action
    e = c.registry_entry
    out = list(e.approved_outbound) if e else []
    kwargs = {"strict_deny_unknown": True, "allowed_tools": (c.tool,), "approved_outbound": out}
    if "declared_kinds" in getattr(ModelProxyPolicy, "__dataclass_fields__", {}):
        kinds = {}
        if contracts is not None and contracts.get(c.tool) is not None:
            kinds = {c.tool: contracts.get(c.tool).kind}
        kwargs["declared_kinds"] = kinds
    policy = ModelProxyPolicy(**kwargs)
    frozen, v = screen_action(policy, c.tool, args if args is not None else {})
    if v.action == "flag":
        v = ProxyVerdict(
            action="block",
            reason="Exact trusted approval required; flag is not execution authority",
            signals=list(v.signals) + [_REVIEW],
        )
    if contracts is not None or approvals is not None:
        from adom.enforcement.review import resolve
        v, _, _ = resolve(c.tool, frozen, v, contracts=contracts, approvals=approvals,
                          agent_id=agent_id)
    sig = tuple(v.signals)
    if v.action == "allow":
        return TierDecision(ALLOW, "", sig)
    if (v.action == "block" and e is not None and e.agent_approval and _REVIEW in sig
            and not any(s.startswith("contract:") for s in sig)
            and not any(h in s for s in sig for h in _HARD)):
        ok, why = prompt_confirmed
        if ok:
            return TierDecision(DEFER, "kernel review delegated to agent approval (registry opt-in)",
                                sig + ("tier:agent_approval_review",))
        return TierDecision(BLOCK, f"{v.reason}; agent_approval not honored: {why}",
                            sig + ("tier:agent_approval_unconfirmed",))
    return TierDecision(BLOCK, v.reason or "kernel denied", sig)
