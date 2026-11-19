#!/usr/bin/env python3
"""Key-free latency, benign utility, and multi-encoding exfiltration benchmark for ADOM.

The benchmark now lives in `adom/bench.py` so `adom bench` works from an installed package.
This path is kept because `evidence/2026-11-15` and the docs cite it; it runs the same code.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adom.bench import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
