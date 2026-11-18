"""ADOM checks for coding agents - Cursor and Claude Code (v0.4).

Three deterministic checks, no model, no network:

  1. self_protection   - the agent may not modify ADOM's own hook, config or policy files
                         (and a changed hooks.json is detected against a human-set baseline).
  2. package_lookalike - install commands are checked for names that closely resemble a
                         well-known package without being it (reuses ADOM supply_chain helpers).
  3. secret_in_code    - edits/writes that put a real-looking credential into a source file
                         are flagged (reuses ADOM's secret shapes from egress_proxy).

Each check returns a list of findings: {"check", "action": "block"|"flag", "reason"}.
Compatible with Python 3.9 (macOS system python).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional

for _p in (Path(__file__).resolve().parent.parent, Path(__file__).resolve().parent):
    if str(_p) not in sys.path:                  # ADOM root, and this folder
        sys.path.insert(0, str(_p))

from adom.enforcement.egress_proxy import _SECRET_RX
from adom.enforcement.supply_chain import _edit_distance_le, _norm_name

HOME = Path.home()
HOOK_DIR = Path(__file__).resolve().parent               # .../ADOM/cursor_hook
ADOM_ROOT = HOOK_DIR.parent                              # .../ADOM
CURSOR_HOOKS_JSON = HOME / ".cursor" / "hooks.json"
ADOM_STATE_DIR = HOME / ".adom"
BASELINE_FILE = ADOM_STATE_DIR / "cursor" / "trusted_config.json"

# ---------------------------------------------------------------- 1. self-protection
# Files the hook depends on. Directories protect everything beneath them.
CLAUDE_SETTINGS = HOME / ".claude" / "settings.json"
PROTECTED_PATHS = [
    CURSOR_HOOKS_JSON,
    CLAUDE_SETTINGS,
    HOME / ".claude" / "settings.local.json",
    HOME / ".cursor" / "mcp.json",
    HOME / ".vscode" / "mcp.json",
    HOME / ".mcp.json",
    HOME / ".claude.json",
    HOME / ".codex" / "config.toml",
    ADOM_STATE_DIR,
    HOOK_DIR,
    ADOM_ROOT / "adom" / "api" / "model_proxy.py",
    ADOM_ROOT / "adom" / "enforcement" / "action_kernel.py",
    ADOM_ROOT / "adom" / "enforcement" / "egress_proxy.py",
    ADOM_ROOT / "adom" / "enforcement" / "supply_chain.py",
    ADOM_ROOT / "adom" / "enforcement" / "action_tiers.py",
    ADOM_ROOT / "adom" / "enforcement" / "approvals.py",
    ADOM_ROOT / "adom" / "enforcement" / "tool_contracts.py",
    ADOM_ROOT / "adom" / "enforcement" / "review.py",
    ADOM_ROOT / "adom" / "enforcement" / "audit_chain.py",
]

# Text markers for shell commands / tool arguments that name a protected location.
# Deliberately conservative: any mention is treated as touching protected state.
_PROTECTED_MARKERS = [
    "hooks.json",
    ".claude/settings",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".mcp.json",
    ".claude/mcp.json",
    ".claude.json",
    "claude_desktop_config.json",
    ".codex/config.toml",
    ".adom/",
    "/.adom",
    "cursor_hook",
    "adom_cursor_",
    "adom_claude_",
    "trusted_config.json",
    "adom/api/model_proxy",
    "adom/enforcement/action_kernel",
    "adom/enforcement/egress_proxy",
    "adom/enforcement/supply_chain",
    "adom/enforcement/action_tiers",
    "tool_tiers.json",
    # Approvals and contracts: the agent must not approve its own actions, read the key,
    # or rewrite what its tools are declared to do.
    "adom/enforcement/approvals",
    "adom/enforcement/tool_contracts",
    "adom/enforcement/review",
    "adom/enforcement/audit_chain",
    "enforcement.approvals",
    "approvalstore",
    "approvals.sqlite",
    "approval.key",
    # contracts.json is not listed by name: projects have their own files called that.
    # ~/.adom/contracts.json is covered by the ".adom/" markers above.
]

# Tools that only look at files. Everything else that names a protected path is blocked.
_READ_ONLY_TOOLS = {"read", "grep", "glob", "ls", "list", "search", "codebase_search",
                    "semanticsearch", "fileSearch".lower()}


# Claude Code tools that can change files. Its other tools (TodoWrite, WebSearch, Task...)
# cannot, so self-protection and secret checks do not apply to them.
_CLAUDE_WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit"}


def _is_write_tool(payload: dict) -> bool:
    tool = str(payload.get("tool_name") or "").lower()
    if payload.get("_adom_agent") == "claude_code":
        return tool in _CLAUDE_WRITE_TOOLS
    return tool not in _READ_ONLY_TOOLS and tool != "shell"


def _canon(p: str, cwd: str = "") -> str:
    p = os.path.expanduser(str(p or "").strip())
    if not p:
        return ""
    if not os.path.isabs(p) and cwd:
        p = os.path.join(cwd, p)
    return os.path.realpath(p).lower()          # macOS volumes are case-insensitive


_PROTECTED_CANON = [os.path.realpath(str(p)).lower() for p in PROTECTED_PATHS]


def is_protected_path(path: str, cwd: str = "") -> bool:
    c = _canon(path, cwd)
    if not c:
        return False
    for prot in _PROTECTED_CANON:
        if c == prot or c.startswith(prot.rstrip("/") + "/"):
            return True
    return False


def mentions_protected(text: str) -> Optional[str]:
    t = str(text or "").lower().replace("\\", "/")
    # Also strip trivial shell quoting/escaping (~/.a''dom, ~/.cu\rsor -> ~/.adom, ~/.cursor)
    t_unquoted = re.sub(r"['\"\\]", "", str(text or "")).lower().replace("\\", "/")
    for variant in (t, t_unquoted):
        for m in _PROTECTED_MARKERS:
            if m in variant:
                return m
    return None


def _strings(obj, out: List[str], depth: int = 0):
    if depth > 20 or len(out) > 2000:
        return
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _strings(k, out, depth + 1)
            _strings(v, out, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _strings(v, out, depth + 1)


def check_self_protection(event: str, payload: dict) -> List[Dict]:
    f = []
    cwd = str(payload.get("cwd") or "")
    if event == "beforeShellExecution":
        cmd = str(payload.get("command") or "")
        m = mentions_protected(cmd)
        if m or (cwd and is_protected_path(cwd)):
            f.append({"check": "self_protection", "action": "block",
                      "reason": "command touches ADOM's protected hook/config files"
                                + (f" ({m})" if m else " (working directory is protected)")})
    elif event == "beforeMCPExecution":
        vals: List[str] = []
        raw = payload.get("tool_input")
        try:
            _strings(json.loads(raw) if isinstance(raw, str) else raw, vals)
        except ValueError:
            vals.append(str(raw))
        hit = next((mentions_protected(v) for v in vals if mentions_protected(v)), None)
        if hit or any(is_protected_path(v, cwd) for v in vals if len(v) < 1024 and "/" in v):
            f.append({"check": "self_protection", "action": "block",
                      "reason": "MCP tool call references ADOM's protected files"})
    elif event == "preToolUse":
        tool = str(payload.get("tool_name") or "")
        if not _is_write_tool(payload):
            return f                             # reads allowed; shell handled by its own hook
        vals = []
        _strings(payload.get("tool_input"), vals)
        paths = [v for v in vals if len(v) < 1024 and ("/" in v or v.startswith("~"))]
        if any(is_protected_path(p, cwd) for p in paths) or \
                any(mentions_protected(p) for p in paths):
            f.append({"check": "self_protection", "action": "block",
                      "reason": f"'{tool}' would modify ADOM's protected hook/config files"})
    elif event == "afterFileEdit":
        if is_protected_path(str(payload.get("file_path") or "")):
            f.append({"check": "self_protection", "action": "flag",
                      "reason": "TAMPER ALERT: a protected ADOM file was edited"})
    return f


def file_sha256(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def config_status(key: str = "hooks_json_sha256") -> Dict:
    """Compare a watched config file with the baseline a human trusted (watch.py --trust)."""
    import adom_cursor_health as health
    return health.baseline_status(key)


def trust_current_config() -> Dict:
    """Trust the current content of every watched config file (Cursor + Claude Code)."""
    import adom_cursor_health as health
    return health.trust_all()


# ---------------------------------------------------------------- 2. package lookalikes
POPULAR_NPM = set("""
react react-dom next vue svelte nuxt express koa fastify lodash underscore axios node-fetch
typescript ts-node tsx webpack vite rollup esbuild parcel babel-loader jest mocha chai sinon
vitest eslint prettier chalk commander yargs inquirer debug dotenv cors helmet morgan
body-parser cookie-parser multer nodemailer mongoose sequelize knex prisma typeorm pg mysql
mysql2 redis ioredis socket.io ws jsonwebtoken bcrypt bcryptjs passport uuid nanoid moment
dayjs date-fns luxon zod yup joi formik redux react-redux zustand mobx rxjs graphql
apollo-server tailwindcss postcss autoprefixer sass styled-components classnames clsx
three d3 chart.js electron react-native expo puppeteer playwright cheerio sharp winston
pino nodemon concurrently cross-env rimraf glob fs-extra semver async bluebird qs
stripe openai react-router react-router-dom framer-motion swr immer ajv minimist
""".split())

POPULAR_PYPI = set("""
requests numpy pandas scipy matplotlib seaborn plotly flask django fastapi uvicorn gunicorn
pydantic sqlalchemy alembic pytest pytest-cov tox nox boto3 botocore urllib3 setuptools wheel
pip six python-dateutil pyyaml jinja2 click typer rich httpx aiohttp beautifulsoup4 lxml
pillow scikit-learn tensorflow torch torchvision transformers datasets tokenizers openai
anthropic langchain psycopg2 psycopg2-binary pymongo redis celery black flake8 mypy ruff
isort pylint tqdm cryptography pyjwt paramiko selenium playwright opencv-python streamlit
jupyter notebook ipython sympy networkx pytz certifi idna charset-normalizer attrs packaging
protobuf grpcio docker kubernetes colorama python-dotenv tomli toml markdown qiskit
websockets marshmallow werkzeug itsdangerous gradio polars pyarrow numba scapy boto
""".split())

# Real, legitimate packages whose names happen to sit close to a popular one.
# They are exempt, but are not themselves used as comparison targets.
KNOWN_LEGIT_NEAR = {"npm": {"preact"}, "pypi": set()}

_PIP_ARG_FLAGS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i",
                  "--index-url", "--extra-index-url", "-t", "--target", "-f", "--find-links",
                  "--prefix", "--root", "--python", "-p"}
_NPM_ARG_FLAGS = {"--registry", "--prefix", "--cache", "-w", "--workspace", "--filter"}


def _segments(command: str) -> List[List[str]]:
    """Split a shell command into simple-command token lists at && || ; | operators."""
    lex = shlex.shlex(command, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    segs, cur = [], []
    for tok in lex:
        if tok and set(tok) <= set("&|;()"):
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(tok)
    if cur:
        segs.append(cur)
    return segs


def _strip_prefix(seg: List[str]) -> List[str]:
    i = 0
    while i < len(seg) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[i]) or
                            seg[i] in ("sudo", "env", "command", "time", "nohup")):
        i += 1
    return seg[i:]


def _collect(args: List[str], arg_flags) -> List[str]:
    names, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a in arg_flags:
            skip = True
            continue
        if a.startswith("-"):
            continue
        names.append(a)
    return names


def installed_packages(command: str) -> List[Dict]:
    """Return [{"ecosystem": "npm"|"pypi", "name": ...}] for package installs in a command."""
    try:
        segs = _segments(command)
    except ValueError:
        return []                                   # unparseable: other checks still apply
    out = []
    for seg in segs:
        s = _strip_prefix(seg)
        if not s:
            continue
        tool = os.path.basename(s[0])
        rest = s[1:]
        eco, names = None, []
        if tool in ("npm", "pnpm", "yarn", "bun"):
            if rest and rest[0] in ("install", "i", "add", "isntall", "in"):
                eco, names = "npm", _collect(rest[1:], _NPM_ARG_FLAGS)
        elif tool in ("npx", "pnpx", "bunx"):
            n = _collect(rest, _NPM_ARG_FLAGS)
            eco, names = "npm", n[:1]
        elif tool in ("pip", "pip3") or re.fullmatch(r"pip3\.\d+", tool):
            if rest and rest[0] == "install":
                eco, names = "pypi", _collect(rest[1:], _PIP_ARG_FLAGS)
        elif re.fullmatch(r"python(3(\.\d+)?)?", tool) and rest[:3] == ["-m", "pip", "install"]:
            eco, names = "pypi", _collect(rest[3:], _PIP_ARG_FLAGS)
        elif tool == "uv" and (rest[:2] == ["pip", "install"] or rest[:1] == ["add"]):
            eco, names = "pypi", _collect(rest[2:] if rest[0] == "pip" else rest[1:], _PIP_ARG_FLAGS)
        elif tool == "poetry" and rest[:1] == ["add"]:
            eco, names = "pypi", _collect(rest[1:], _PIP_ARG_FLAGS)
        elif tool == "pipx" and rest[:1] in (["install"], ["run"]):
            eco, names = "pypi", _collect(rest[1:], _PIP_ARG_FLAGS)[:1]
        for n in names:
            name = _package_name(n, eco)
            if name:
                out.append({"ecosystem": eco, "name": name})
    return out


def _package_name(spec: str, eco: str) -> Optional[str]:
    spec = spec.strip()
    # local paths, URLs, archives, requirement files are not registry names
    if (not spec or "/" in spec and not spec.startswith("@") or spec.startswith((".", "~"))
            or "://" in spec or spec.startswith("git+")
            or spec.endswith((".whl", ".tar.gz", ".zip", ".tgz", ".txt"))):
        return None
    if eco == "npm":
        if spec.startswith("@"):                    # @scope/name@version
            parts = spec.split("@")
            return ("@" + parts[1]).lower() if len(parts) > 1 else None
        return spec.split("@")[0].lower() or None
    name = re.split(r"[<>=!~\[;@ ]", spec)[0]
    return name.lower() or None


def _pep503(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n).lower()


def _one_adjacent_swap(a: str, b: str) -> bool:
    """True if b is a with exactly one pair of neighbouring characters swapped
    ('reqeusts' vs 'requests'). Plain edit distance counts this as 2."""
    if len(a) != len(b) or a == b:
        return False
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    return (len(diff) == 2 and diff[1] == diff[0] + 1
            and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])


def lookalike_of(name: str, eco: str, extra_allowed: Iterable[str] = ()) -> Optional[str]:
    known = POPULAR_NPM if eco == "npm" else POPULAR_PYPI
    allowed = set(known) | KNOWN_LEGIT_NEAR[eco] | {a.lower() for a in extra_allowed}
    if eco == "pypi":
        if _pep503(name) in {_pep503(k) for k in allowed}:
            return None                             # same package under PyPI normalization
    elif name in allowed or name.startswith("@"):
        return None                                 # exact match, or scoped (not compared)
    n = _norm_name(name)
    if len(n) < 5:
        return None                                 # too short to compare meaningfully
    limit = 2 if len(n) >= 10 else 1
    for k in sorted(known):
        kn = _norm_name(k)
        if n == kn or _edit_distance_le(n, kn, limit) or _one_adjacent_swap(n, kn):
            return k
    return None


def _load_extra_allowed() -> List[str]:
    try:
        cfg = json.loads((ADOM_STATE_DIR / "cursor" / "config.json").read_text())
        return [str(x) for x in cfg.get("allowed_packages", [])]
    except (OSError, ValueError):
        return []


def check_packages(event: str, payload: dict) -> List[Dict]:
    if event != "beforeShellExecution":
        return []
    extra = _load_extra_allowed()
    f = []
    for p in installed_packages(str(payload.get("command") or "")):
        near = lookalike_of(p["name"], p["ecosystem"], extra)
        if near:
            f.append({"check": "package_lookalike", "action": "block",
                      "reason": f"{p['ecosystem']} package '{p['name']}' closely resembles "
                                f"'{near}' but is not it (possible typosquat)"})
    return f


# ---------------------------------------------------------------- 3. secrets in code
# Reuse ADOM's key shapes, but drop the loose "password=..." rule: in source code it
# matches ordinary variable assignments. Replace it with a quoted-literal rule.
# ADOM's shapes have no left boundary, so 'sk-...' also matches inside 'task-...' or
# 'disk-...'. For source code, require that the key starts a token.
_CODE_SECRET_RX = [(re.compile(r"(?<![A-Za-z0-9_\-])(?:" + rx.pattern + ")", rx.flags), label)
                   for rx, label in _SECRET_RX if label != "credential_kv"] + [
    (re.compile(r"""(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"""
                r"""\s*[:=]\s*["']([^"'\s]{12,})["']"""), "hardcoded_credential"),
]
_PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|your[_-]|xxxx|dummy|fake|"
                          r"redacted|<[^>]+>|\$\{|\{\{|process\.env|os\.environ|getenv)")
_VAR_TEMPLATE_RX = re.compile(r"(?i)(\$\{|\{\{|process\.env|os\.environ|getenv|<[^>]+>)")
_SHELL_EGRESS_RX = re.compile(
    r"(?i)(?:^|[;&|(\s])(?:curl|wget|nc|ncat|ssh|scp|rsync)\b|https?://|\bfetch\s*\(|\burllib\.|\brequests\."
)
# Files where a secret is expected to live (the fix is not to commit them, not to block edits).
_SECRET_FILE = re.compile(r"(?i)(^|/)(\.env(\..*)?|.*\.(pem|key|p12|pfx)|credentials(\.json)?|"
                          r"secrets?\.(json|ya?ml|toml))$")


def find_secrets(text: str) -> List[str]:
    hits = []
    for rx, label in _CODE_SECRET_RX:
        for m in rx.finditer(text or ""):
            if not _PLACEHOLDER.search(m.group(0)):
                hits.append(label)
                break
    return hits


def find_shell_egress_secrets(command: str) -> List[str]:
    """Detect raw or encoded secrets passed to outbound shell commands/URLs."""
    cmd = str(command or "")
    if not _SHELL_EGRESS_RX.search(cmd):
        return []
    from adom.api.model_proxy import _try_decode_runs
    views = [cmd]
    for tok in re.split(r"[\s,;\"']+", cmd):
        val = tok.split("=", 1)[1] if "=" in tok else tok
        if len(val) >= 16:
            views.extend(_try_decode_runs(val))
        if len(val) >= 24 and len(val) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", val):
            try:
                views.append(bytes.fromhex(val).decode("utf-8", "ignore"))
            except ValueError:
                pass
    hits: List[str] = []
    for view in views:
        for rx, label in _CODE_SECRET_RX:
            if label == "hardcoded_credential":
                continue
            for m in rx.finditer(view):
                if not _VAR_TEMPLATE_RX.search(m.group(0)) and label not in hits:
                    hits.append(label)
                    break
    return hits


def check_secrets(event: str, payload: dict) -> List[Dict]:
    if event == "beforeShellExecution":
        cmd = str(payload.get("command") or "")
        labels = sorted(set(find_shell_egress_secrets(cmd)))
        if not labels:
            return []
        return [{"check": "secret_in_shell_egress", "action": "block",
                 "reason": f"outbound shell command carries credential material ({', '.join(labels)})"}]
    if event == "afterFileEdit":
        path = str(payload.get("file_path") or "")
        texts = [str(e.get("new_string") or "") for e in (payload.get("edits") or [])
                 if isinstance(e, dict)]
        action = "flag"                              # edit already happened; record it
    elif event == "preToolUse":
        tool = str(payload.get("tool_name") or "").lower()
        if not _is_write_tool(payload) or tool.startswith("mcp"):
            return []
        vals: List[str] = []
        _strings(payload.get("tool_input"), vals)
        path = next((v for v in vals if "/" in v and len(v) < 1024 and "\n" not in v), "")
        texts = vals
        action = "block"
    else:
        return []
    if _SECRET_FILE.search(path):
        return []
    labels = sorted({l for t in texts for l in find_secrets(t)})
    if not labels:
        return []
    return [{"check": "secret_in_code", "action": action,
             "reason": f"credential written into source file {os.path.basename(path) or '?'} "
                       f"({', '.join(labels)})"}]


# ---------------------------------------------------------------- entry point
def run_all(event: str, payload: dict) -> List[Dict]:
    findings: List[Dict] = []
    for check in (check_self_protection, check_packages, check_secrets):
        try:
            findings.extend(check(event, payload))
        except Exception as exc:                     # a broken check must not pass silently
            findings.append({"check": check.__name__, "action": "block",
                             "reason": f"check failed: {type(exc).__name__}"})
    return findings
