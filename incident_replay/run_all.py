#!/usr/bin/env python3
"""One-command replay, verification, tests, and manifest generation."""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def run(*args: str) -> None:
    subprocess.run([sys.executable, "-B", *args], cwd=ROOT, check=True)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> int:
    run("incident_replay/replay.py")
    run("incident_replay/verify.py", "incident_replay/results")
    run("-m", "unittest", "discover", "-s", "incident_replay", "-p", "test_*.py", "-v")

    relpaths = [
        "README.md",
        "PUBLIC_BRIEF.md",
        "DEMO_SCRIPT.md",
        "replay.py",
        "verify.py",
        "live_model.py",
        "verify_live.py",
        "test_replay.py",
        "test_live_model.py",
        "test_blast_gateway.py",
        "run_all.py",
        "results/unprotected.json",
        "results/adom.json",
        "results/comparison.json",
    ]
    lines = []
    for rel in relpaths:
        path = HERE / rel
        if not path.is_file():
            raise FileNotFoundError(path)
        # Paths are repository-relative so the standard command
        # `shasum -a 256 -c incident_replay/MANIFEST.sha256` works from the repo root.
        lines.append(f"{sha256(path)}  incident_replay/{rel}")
    for rel in ("adom/enforcement/blast_radius.py", "adom/enforcement/mediated_gateway.py"):
        path = ROOT / rel
        if not path.is_file():
            raise FileNotFoundError(path)
        lines.append(f"{sha256(path)}  {rel}")
    (HERE / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")
    print(f"\nMANIFEST: {HERE / 'MANIFEST.sha256'}")
    print("INCIDENT REPLAY: ALL VERIFIED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
