#!/usr/bin/env bash
# Run an upstream bypass reproduction from a clean checkout of this repository.
#
# For each target this script:
#   1. fetches the exact pinned upstream commit (shallow, by SHA) into reproductions/.work/
#   2. checks the checkout really is that commit
#   3. installs it, with its own dependencies, into an isolated virtualenv
#   4. runs the side-by-side test (upstream bypass + ADOM on the same input)
#
# Usage:   reproductions/run_reproduction.sh <target>...   (or: all)
# Targets: openai-agents  nemo-guardrails  snyk-agent-scan  superagent
#
# Needs: git, bash, curl, Python 3.11-3.13 (NeMo Guardrails pins <3.14).
# Set PYTHON=/path/to/python3.x to choose the interpreter, ADOM_REPRO_WORK to move the
# working folder. Nothing outside that folder is installed or changed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${ADOM_REPRO_WORK:-$ROOT/reproductions/.work}"
PY="${PYTHON:-python3}"

# target | upstream repo | pinned commit | pip install path (in checkout) | env var | value (in checkout) | extra pip | test file
TARGETS=(
  "openai-agents|openai/openai-agents-python|64fbde5d02b42ae5f9db668eb0184cdb3fc9d775|.|OPENAI_AGENTS_SRC|src||openai-agents-guardrail-reproduction/test_handoff_guardrail_repro.py"
  "nemo-guardrails|NVIDIA-NeMo/Guardrails|5d7f4c1ca62fb6155066e6c581379d1a5ec11338|.|NEMO_GUARDRAILS_ROOT|.|detect-secrets==1.5.0|nemo-guardrails-tool-policy-reproduction/test_tool_call_regex_and_secrets_repro.py"
  "snyk-agent-scan|snyk/agent-scan|6eb212583d044f40c8473f62b3e917029ef2cd22|.|SNYK_AGENT_SCAN_SRC|src||snyk-agent-scan-guard-reproduction/test_guard_fail_open_and_redact_repro.py"
  "superagent|superagent-ai/superagent|c9e646271bf15cf7ea7b8e2de9de98008ea1099d|sdk/python|SUPERAGENT_SRC|sdk/python/src||superagent-guard-failopen-reproduction/test_guard_fail_open_repro.py"
)

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

run_target() {
  local want="$1" found=0 line name repo sha pipdir envvar envval extra test
  for line in "${TARGETS[@]}"; do
    IFS='|' read -r name repo sha pipdir envvar envval extra test <<<"$line"
    [ "$name" = "$want" ] || continue
    found=1
    local src="$WORK/$name" venv="$WORK/venv-$name"
    echo "==> $name: $repo @ ${sha:0:12}"
    if [ ! -d "$src/.git" ]; then
      git init -q "$src"
      git -C "$src" remote add origin "https://github.com/$repo"
    fi
    git -C "$src" fetch -q --depth 1 origin "$sha"
    git -C "$src" checkout -q --detach FETCH_HEAD
    if [ "$(git -C "$src" rev-parse HEAD)" != "$sha" ]; then
      echo "pinned commit mismatch for $name" >&2
      return 1
    fi
    if [ ! -x "$venv/bin/python" ]; then
      "$PY" -m venv "$venv"
    fi
    "$venv/bin/python" -m pip install -q --upgrade pip
    # shellcheck disable=SC2086
    "$venv/bin/python" -m pip install -q -e "$src/$pipdir" $extra
    (cd "$ROOT" && env "$envvar=$src/$envval" ADOM_ROOT="$ROOT" \
      "$venv/bin/python" -B -m unittest -v "reproductions/$test")
  done
  if [ "$found" = 0 ]; then
    echo "unknown target: $want" >&2
    usage
  fi
}

[ "$#" -ge 1 ] || usage
mkdir -p "$WORK"
if [ "$1" = "all" ]; then
  set -- openai-agents nemo-guardrails snyk-agent-scan superagent
fi
for t in "$@"; do
  run_target "$t"
done
