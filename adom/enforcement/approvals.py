"""Exact-action approvals for the generic gateway (2026-11-10).

Before this module a `flag` verdict ("review required") was a dead end in the generic
gateway: the kernel turned it into a block and nothing could ever release it. That is safe
and unusable. This is the release path, and it is deliberately narrow:

  * An approval names ONE action: sha256 over (agent id, tool name, canonical frozen
    arguments). Change one byte of one argument and it is a different action.
  * It expires, and it is consumed once. Consumption is an atomic SQLite transaction, so two
    racing calls cannot both spend it.
  * It can only release a `review_required` decision. A hard block (secret in arguments,
    SSRF, unapproved payee, contract violation, ...) is never eligible; the gateway does not
    even look here for those.
  * With a key, each approval row carries an HMAC. Someone who can write the database file
    but does not hold the key cannot mint an approval.

Trust: `approve()` is an operator action. This object, its database and its key belong
outside anything the agent can reach, exactly like the policy and the executor. It is not a
tool and must never be exposed as one. Who the approver is, and whether a person actually
looked, is the calling system's job to establish; the store records the name it is given.

Operator commands (run them yourself, in your own terminal):

    python3 -m adom.enforcement.approvals init                 # once: key + database in ~/.adom
    python3 -m adom.enforcement.approvals list                 # what is waiting, with arguments
    python3 -m adom.enforcement.approvals approve ID --by NAME # ID may be a unique prefix
    python3 -m adom.enforcement.approvals deny ID

`approve` needs an interactive terminal and a typed "yes"; there is no flag to skip that.
On a machine where the agent has a shell under your own account this raises the bar and
leaves a record. It is not a boundary there: the same user can read the key. The boundary
version keeps the store and key under a different account or container than the agent.

Python 3.9+, standard library only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

MAX_TTL_SECONDS = 24 * 3600
MAX_PENDING = 1000
PENDING_MAX_AGE_SECONDS = 24 * 3600
MAX_SHOWN_ARGS = 16384


def _digest_canon(obj: Any) -> Any:
    """Lossless, collision-free canonical representation (bytes vs dicts never collide)."""
    if isinstance(obj, bytes):
        return ["b", obj.hex()]
    if isinstance(obj, dict):
        return ["d", [[str(k), _digest_canon(v)] for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))]]
    if isinstance(obj, tuple):
        return ["t", [_digest_canon(v) for v in obj]]
    if isinstance(obj, list):
        return ["l", [_digest_canon(v) for v in obj]]
    return obj


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return {"__bytes__": obj.hex()}
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return obj


def shown_arguments(frozen_args: Any) -> str:
    """The arguments as the approver will read them. If they do not fit, the text says so
    and the approver should decline: nobody can approve what they cannot see in full."""
    text = json.dumps(_jsonable(frozen_args), sort_keys=True, ensure_ascii=True, indent=1)
    if len(text) > MAX_SHOWN_ARGS:
        return "[ARGUMENTS TOO LARGE TO SHOW IN FULL - DO NOT APPROVE BLIND]\n" + text[:MAX_SHOWN_ARGS]
    return text


def action_digest(agent_id: str, name: str, frozen_args: Any) -> str:
    """Identity of one exact action. `frozen_args` is the kernel's snapshot."""
    body = json.dumps({"agent": agent_id, "tool": name, "args": _digest_canon(frozen_args)},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(body.encode()).hexdigest()


class ApprovalStore:
    def __init__(self, path: str = ":memory:", key: Optional[bytes] = None,
                 clock=time.time):
        if key is not None and (not isinstance(key, (bytes, bytearray)) or len(key) < 32):
            raise ValueError("approval key must be at least 32 bytes")
        self._key = bytes(key) if key is not None else None
        self._clock = clock
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False,
                                   timeout=10)
        self._db.execute("CREATE TABLE IF NOT EXISTS pending ("
                         "digest TEXT PRIMARY KEY, agent TEXT, tool TEXT, summary TEXT, "
                         "requested REAL, arguments TEXT DEFAULT '')")
        self._db.execute("CREATE TABLE IF NOT EXISTS approvals ("
                         "id INTEGER PRIMARY KEY AUTOINCREMENT, digest TEXT NOT NULL, "
                         "approver TEXT NOT NULL, expires REAL NOT NULL, nonce TEXT NOT NULL, "
                         "mac TEXT NOT NULL, consumed REAL)")

    # ---- integrity
    def _mac(self, digest: str, approver: str, expires: float, nonce: str) -> str:
        msg = f"{digest}|{approver}|{expires!r}|{nonce}".encode()
        if self._key is None:
            return hashlib.sha256(msg).hexdigest()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    # ---- gateway side
    def request(self, digest: str, agent_id: str, tool: str, summary: str = "",
                arguments: str = "") -> bool:
        """Record that an action is waiting for a person, with the exact arguments they
        would be approving. Bounded; stale requests age out; returns False when full."""
        now = self._clock()
        with self._lock:
            self._db.execute("DELETE FROM pending WHERE requested < ?",
                             (now - PENDING_MAX_AGE_SECONDS,))
            if self._db.execute("SELECT 1 FROM pending WHERE digest=?", (digest,)).fetchone():
                return True
            n = self._db.execute("SELECT COUNT(*) FROM pending").fetchone()[0]
            if n >= MAX_PENDING:
                return False
            self._db.execute("INSERT INTO pending VALUES (?,?,?,?,?,?)",
                             (digest, agent_id[:200], tool[:256], summary[:2000], now,
                              arguments[:MAX_SHOWN_ARGS + 100]))
            return True

    def consume(self, digest: str) -> Optional[str]:
        """Spend one live approval for exactly this action. Returns the approver, or None."""
        now = self._clock()
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                rows = self._db.execute(
                    "SELECT id, approver, expires, nonce, mac FROM approvals "
                    "WHERE digest=? AND consumed IS NULL ORDER BY id", (digest,)).fetchall()
                for rid, approver, expires, nonce, mac in rows:
                    if expires <= now:
                        continue
                    if not hmac.compare_digest(mac, self._mac(digest, approver, expires, nonce)):
                        continue                      # row not written by a key holder
                    self._db.execute("UPDATE approvals SET consumed=? WHERE id=?", (now, rid))
                    self._db.execute("DELETE FROM pending WHERE digest=?", (digest,))
                    self._db.execute("COMMIT")
                    return approver
                self._db.execute("COMMIT")
                return None
            except Exception:
                try:
                    self._db.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    # ---- operator side
    def pending(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._db.execute("SELECT digest, agent, tool, summary, requested, arguments "
                                    "FROM pending ORDER BY requested").fetchall()
        return [dict(zip(("digest", "agent", "tool", "summary", "requested", "arguments"), r))
                for r in rows]

    def approve(self, digest: str, approver: str, ttl_seconds: float = 300) -> float:
        """Operator approves one exact action. Returns the expiry time."""
        if not isinstance(digest, str) or len(digest) != 64 or \
                any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("digest must be a sha256 hex string")
        if not isinstance(approver, str) or not approver.strip() or "|" in approver:
            raise ValueError("approver must be a non-empty name without '|'")
        if not (0 < ttl_seconds <= MAX_TTL_SECONDS):
            raise ValueError("ttl must be positive and at most 24 hours")
        expires = self._clock() + float(ttl_seconds)
        nonce = os.urandom(16).hex()
        with self._lock:
            self._db.execute(
                "INSERT INTO approvals (digest, approver, expires, nonce, mac) VALUES (?,?,?,?,?)",
                (digest, approver, expires, nonce, self._mac(digest, approver, expires, nonce)))
        return expires

    def deny(self, digest: str) -> None:
        """Operator declines: drop the pending request and any unspent approval for it."""
        with self._lock:
            self._db.execute("DELETE FROM pending WHERE digest=?", (digest,))
            self._db.execute("UPDATE approvals SET consumed=-1 WHERE digest=? AND consumed IS NULL",
                             (digest,))


# ----------------------------------------------------------------------------- operator CLI
def _open(directory: str) -> "ApprovalStore":
    from pathlib import Path
    from adom.enforcement.audit_chain import load_key
    d = Path(directory).expanduser()
    db, key = d / "approvals.sqlite", d / "approval.key"
    if not db.exists() or not key.exists():
        raise SystemExit(f"no approval store in {d}; run: python3 -m adom.enforcement.approvals init")
    return ApprovalStore(str(db), key=load_key(key))


def _match(store: "ApprovalStore", ident: str) -> Dict[str, Any]:
    ident = ident.strip().lower()
    if len(ident) < 8:
        raise SystemExit("give at least 8 characters of the approval id")
    hits = [p for p in store.pending() if p["digest"].startswith(ident)]
    if len(hits) != 1:
        raise SystemExit("no pending action with that id" if not hits
                         else "that id matches more than one pending action; give more characters")
    return hits[0]


def _show(p: Dict[str, Any]) -> None:
    print(f"id      {p['digest']}")
    print(f"agent   {p['agent']}")
    print(f"tool    {p['tool']}")
    print(f"why     {p['summary']}")
    print(f"waiting {int(time.time() - p['requested'])}s")
    print("arguments:")
    print("  " + (p["arguments"] or "(not recorded)").replace("\n", "\n  "))


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    import sys
    from pathlib import Path
    ap = argparse.ArgumentParser(prog="adom.enforcement.approvals")
    ap.add_argument("--dir", default="~/.adom", help="operator state directory")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("list")
    a = sub.add_parser("approve")
    a.add_argument("id")
    a.add_argument("--by", required=True, help="your name, recorded with the approval")
    a.add_argument("--ttl", type=float, default=300, help="seconds the approval stays valid")
    a.add_argument("--allow-truncated", action="store_true",
                   help="explicit opt-in required to approve actions whose shown arguments were truncated")
    d = sub.add_parser("deny")
    d.add_argument("id")
    o = ap.parse_args(argv)

    if o.cmd == "init":
        directory = Path(o.dir).expanduser()
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        key = directory / "approval.key"
        if key.exists():
            print(f"{key} already exists; left as it is")
        else:
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(os.urandom(32).hex() + "\n")
            print(f"created {key}")
        _open(str(directory)) if (directory / "approvals.sqlite").exists() else \
            ApprovalStore(str(directory / "approvals.sqlite"), key=key.read_bytes().strip())
        os.chmod(directory / "approvals.sqlite", 0o600)
        print(f"approval store ready in {directory}")
        return 0

    store = _open(o.dir)
    if o.cmd == "list":
        pending = store.pending()
        if not pending:
            print("nothing is waiting for approval")
        for p in pending:
            _show(p)
            print("-" * 60)
        return 0
    p = _match(store, o.id)
    if o.cmd == "deny":
        store.deny(p["digest"])
        print("denied " + p["digest"])
        return 0
    _show(p)
    if str(p.get("arguments", "")).startswith("[ARGUMENTS TOO LARGE TO SHOW IN FULL") and not o.allow_truncated:
        print("refusing blind approval of truncated arguments without --allow-truncated", file=sys.stderr)
        return 4
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("approve needs an interactive terminal: a person has to read the action above "
              "and type yes", file=sys.stderr)
        return 3
    if input('Type "yes" to approve exactly this action once: ').strip() != "yes":
        print("not approved")
        return 1
    expires = store.approve(p["digest"], o.by, ttl_seconds=o.ttl)
    print(f"approved by {o.by}; valid for {int(expires - time.time())}s, one use")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
