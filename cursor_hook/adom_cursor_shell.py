"""ADOM shell policy for coding agents in Cursor (v0.3, narrow).

ADOM's core ModelProxyPolicy treats shell execution as allowlist-only and blocks any
command containing shell operators. In a real Cursor session that blocked 9 of 9
ordinary commands (pytest, venv creation, pip install pytest, ls).

This policy is for a developer workstation:
  block - ADOM's privilege-escalation / sandbox-escape signatures, with two rules
          tuned so ordinary developer commands no longer match them
  allow - everything else (still logged, and still subject to the self-protection
          and package-lookalike checks in adom_cursor_checks.py)

Deterministic regex matching. No model, no network. Python 3.9 compatible.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict

if str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from adom.api.model_proxy import _ESCAPE_RX

POLICY_VERSION = "cursor-shell-2026.09.22-narrow"

# ADOM's signatures, reused verbatim where they are precise.
_REUSED = {"host_cred_access", "container_socket", "namespace_break", "reverse_shell",
           "kernel_module", "k8s_escape"}

# Two ADOM rules are too broad for developers and are replaced here:
#   privilege_escalation: ADOM's version also matches 'chmod 755 script.sh'.
#     Tuned: sudo/doas/setcap/setuid, symbolic setuid (u+s), or a 4-digit mode whose
#     first digit sets the setuid/setgid bits (e.g. 4755, 2755).
#   host_breakout: ADOM's version also matches '../../../' in ordinary relative paths.
#     Tuned: chroot, or an explicit /host/ mount path.
SIGNATURES = [(rx, label) for rx, label in _ESCAPE_RX if label in _REUSED] + [
    (re.compile(r"\bsudo\b|\bdoas\b|\bsetcap\b|\bsetuid\b"
                r"|\bchmod\s+(?:-\w+\s+)*[ugoa]*\+[rwxX]*s"
                r"|\bchmod\s+(?:-\w+\s+)*[2-7][0-7]{3}\b", re.I),
     "privilege_escalation"),
    (re.compile(r"\bchroot\b|(?:^|\s)/host/", re.I), "host_breakout"),
]


def decide(command: str) -> Dict:
    """Return {"action": "allow"|"block", "reason": str, "signals": [..]}."""
    cmd = str(command or "")
    for rx, label in SIGNATURES:
        if rx.search(cmd):
            return {"action": "block", "signals": [f"shell:{label}"],
                    "reason": f"command matches ADOM {label.replace('_', ' ')} signature"}
    return {"action": "allow", "reason": "", "signals": ["shell:dev_default_allow"]}
