#!/usr/bin/env python3
"""Build, run, inspect, and verify the Docker topology. No API keys required."""
from __future__ import annotations

import json
import hashlib
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
COMPOSE = HERE / "compose.yaml"
PROJECT = "adom-incident-replay"
RUNTIME = HERE / "runtime"


def docker(*args, capture=False):
    cmd = ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE), *args]
    return subprocess.run(cmd, cwd=HERE, check=True, text=True,
                          capture_output=capture)


def prepare():
    for part in ("evidence", "agent_off", "agent_adom"):
        (RUNTIME / part).mkdir(parents=True, exist_ok=True)
    for path in [
        RUNTIME / "evidence/cache.jsonl", RUNTIME / "evidence/scorer.jsonl",
        RUNTIME / "evidence/target.jsonl", RUNTIME / "evidence/broker.jsonl",
        RUNTIME / "agent_off/summary.json", RUNTIME / "agent_adom/summary.json",
        RUNTIME / "topology.json", RUNTIME / "verification.json",
    ]:
        if path.exists():
            path.unlink()


def topology():
    out = {}
    for service in ("agent-adom", "broker", "target", "cache", "scorer"):
        # Agent jobs have exited by the time topology is captured, so include stopped
        # one-off containers. They are retained until the final compose down.
        cid = docker("ps", "--all", "-q", service, capture=True).stdout.strip().splitlines()
        cid = cid[-1] if cid else ""
        if not cid:
            raise RuntimeError(f"missing running container: {service}")
        raw = subprocess.run(["docker", "inspect", cid], check=True, text=True,
                             capture_output=True).stdout
        info = json.loads(raw)[0]
        out[service] = sorted(info["NetworkSettings"]["Networks"].keys())
    (RUNTIME / "topology.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")


def write_manifest():
    relpaths = [
        "Dockerfile", "compose.yaml", "service.py", "broker.py", "agent.py",
        "verify_container.py", "run_lab.py", "README.md",
        "runtime/topology.json", "runtime/verification.json",
        "runtime/agent_off/summary.json", "runtime/agent_adom/summary.json",
        "runtime/evidence/cache.jsonl", "runtime/evidence/scorer.jsonl",
        "runtime/evidence/target.jsonl", "runtime/evidence/broker.jsonl",
    ]
    files = [(HERE / rel, f"incident_replay/container_lab/{rel}") for rel in relpaths]
    files.extend([
        (ROOT / "adom/api/model_proxy.py", "adom/api/model_proxy.py"),
        (ROOT / "adom/enforcement/action_kernel.py", "adom/enforcement/action_kernel.py"),
        (ROOT / "adom/enforcement/egress_proxy.py", "adom/enforcement/egress_proxy.py"),
        (ROOT / "adom/enforcement/blast_radius.py", "adom/enforcement/blast_radius.py"),
    ])
    lines = []
    for path, label in files:
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{h}  {label}")
    (HERE / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")


def main():
    prepare()
    try:
        docker("down", "--remove-orphans")
        # Every service has its own Compose image name even though they share a
        # Dockerfile.  Building only the long-running services can therefore
        # leave the one-shot agents on stale code.  Build the complete topology
        # first so evidence and the manifest always describe one source tree.
        docker("build")
        docker("up", "-d", "cache", "scorer", "target", "broker")
        docker("run", "agent-off")
        docker("run", "agent-adom")
        topology()
        subprocess.run([sys.executable, "-B", str(HERE / "verify_container.py")],
                       cwd=HERE, check=True)
        write_manifest()
    finally:
        docker("down", "--remove-orphans")
    print(f"Evidence: {RUNTIME / 'verification.json'}")
    print(f"Manifest: {HERE / 'MANIFEST.sha256'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
