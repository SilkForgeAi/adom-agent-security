"""Append-only audit chain with an optional key and an explicit head anchor (2026-11-10).

Record format is the one the coding-agent hooks and the MCP gateway already write:

    record["hash"] = sha256(prev_hash + canonical body)

so every existing log and every existing verifier keeps working. Two additions:

  * KEYED mode. With a key, each record also carries
        record["mac"] = HMAC-SHA256(key, prev_hash + canonical body without mac/hash)
    The mac sits inside the hashed body, so an unkeyed verifier still links the chain.
    Someone who can write the file but does not hold the key can no longer rewrite the
    whole log: they cannot produce valid macs.

  * HEAD ANCHOR. `head()` returns (count, last_hash). Store that pair somewhere the writer
    of the log cannot reach, and pass it back to `verify_chain(expected_head=...)`. That is
    what detects a truncated tail. A hash chain alone cannot: a log cut after record N is a
    perfectly valid chain of N records.

What this still does not do: a key kept beside the log protects nothing, and without an
external anchor a truncated tail is undetectable. Neither is a signature by a third party.

Python 3.9+, standard library only. Safe across processes (flock).
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

GENESIS = "0" * 64


def _canon(record: Dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def load_key(path: Optional[os.PathLike]) -> Optional[bytes]:
    """Read an audit key file. Refuses short keys and group/world-readable files."""
    if not path:
        return None
    p = Path(path)
    st = p.stat()
    if st.st_mode & 0o077:
        raise ValueError(f"audit key file {p} must not be readable by group or others")
    key = p.read_bytes().strip()
    if len(key) < 32:
        raise ValueError("audit key must be at least 32 bytes")
    return key


class ChainLog:
    def __init__(self, path: os.PathLike, key: Optional[bytes] = None,
                 anchor_path: Optional[os.PathLike] = None):
        """anchor_path: a second file, rewritten after every append with the current head
        ("COUNT:HASH"). Put it where whoever can write the log cannot: another volume,
        another account, a mounted share. `read_anchor()` + `verify_chain(expected_head=)`
        then detects a truncated or rewritten log without anyone pinning the head by hand.
        If the anchor cannot be written the append raises, so callers that stop on a failed
        append (the gateways) also stop on a lost anchor."""
        if key is not None and (not isinstance(key, (bytes, bytearray)) or len(key) < 32):
            raise ValueError("audit key must be at least 32 bytes")
        self.anchor_path = Path(anchor_path) if anchor_path else None
        self.path = Path(path)
        self.key = bytes(key) if key is not None else None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass

    @property
    def keyed(self) -> bool:
        return self.key is not None

    def _last(self) -> Tuple[str, Optional[int]]:
        """(last hash, last seq or None when the last record predates seq numbers)."""
        try:
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 65536))
                lines = f.read().splitlines()
            if not lines:
                return GENESIS, 0
            last = json.loads(lines[-1])
            seq = last.get("seq")
            return last["hash"], seq if type(seq) is int else None
        except (OSError, ValueError, KeyError, IndexError):
            return GENESIS, 0

    def _last_hash(self) -> str:
        return self._last()[0]

    def append(self, record: Dict[str, Any]) -> str:
        """Append one record; returns its hash. Raises if the record cannot be made durable."""
        with open(self.path.with_name(self.path.name + ".lock"), "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            record.pop("hash", None)
            record.pop("mac", None)
            record["prev_hash"], seq = self._last()
            if seq is None:                       # older log without seq: count it once
                seq = self.head()[0]
            record["seq"] = seq + 1
            if self.key is not None:
                record["mac"] = hmac.new(
                    self.key, (record["prev_hash"] + _canon(record)).encode(),
                    hashlib.sha256).hexdigest()
            record["hash"] = hashlib.sha256(
                (record["prev_hash"] + _canon(record)).encode()).hexdigest()
            with open(self.path, "a") as f:
                f.write(json.dumps(record, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            if self.anchor_path is not None:
                tmp = self.anchor_path.with_name(self.anchor_path.name + ".tmp")
                with open(tmp, "w") as f:
                    f.write(f"{record['seq']}:{record['hash']}\n")
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.anchor_path)
            return record["hash"]

    def head(self) -> Tuple[int, str]:
        """(record count, last hash). Pin this outside the log's reach to detect truncation."""
        try:
            lines = self.path.read_text().splitlines()
        except OSError:
            return 0, GENESIS
        if not lines:
            return 0, GENESIS
        return len(lines), json.loads(lines[-1])["hash"]


def read_anchor(path: os.PathLike) -> Tuple[int, str]:
    """Parse an anchor file ("COUNT:HASH") into the pair verify_chain(expected_head=) takes."""
    count, _, want = Path(path).read_text().strip().partition(":")
    if len(want) != 64:
        raise ValueError("anchor file is not COUNT:HASH")
    return int(count), want


def verify_chain(path: os.PathLike, key: Optional[bytes] = None,
                 expected_head: Optional[Tuple[int, str]] = None) -> Tuple[bool, str]:
    """Independent check of a log. Returns (ok, explanation).

    key           : when given, every record must carry a valid mac (an unkeyed record in a
                    log that is supposed to be keyed is a failure, not a pass).
    expected_head : (count, hash) pinned earlier. The log must still contain that record at
                    that position; fewer records, or a different hash there, fails.
    """
    prev = GENESIS
    try:
        lines = Path(path).read_text().splitlines()
    except OSError as exc:
        return False, f"cannot read log: {exc}"
    hashes = []
    for i, line in enumerate(lines, 1):
        try:
            r = json.loads(line)
        except ValueError:
            return False, f"record {i}: not JSON"
        if not isinstance(r, dict):
            return False, f"record {i}: not JSON"
        h = r.pop("hash", None)
        if r.get("prev_hash") != prev:
            return False, f"record {i}: prev_hash does not link (record removed or reordered)"
        if hashlib.sha256((prev + _canon(r)).encode()).hexdigest() != h:
            return False, f"record {i}: hash mismatch (record modified)"
        if "seq" in r and r["seq"] != i:
            return False, f"record {i}: sequence number is {r['seq']!r} (records missing before it)"
        if key is not None:
            mac = r.pop("mac", None)
            want = hmac.new(key, (prev + _canon(r)).encode(), hashlib.sha256).hexdigest()
            if not isinstance(mac, str) or not hmac.compare_digest(mac, want):
                return False, f"record {i}: mac missing or wrong (not written with this key)"
        prev = h
        hashes.append(h)
    if expected_head is not None:
        count, want_hash = expected_head
        if count < 0 or len(hashes) < count:
            return False, (f"log has {len(hashes)} records but {count} were pinned "
                           f"(tail truncated)")
        at = hashes[count - 1] if count else GENESIS
        if at != want_hash:
            return False, f"record {count}: does not match the pinned head (log rewritten)"
    return True, f"{len(lines)} records, chain intact" + (", macs valid" if key else "")
