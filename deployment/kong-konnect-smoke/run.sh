#!/usr/bin/env bash
# ADOM + Kong AI Gateway smoke test against a real Kong Enterprise data plane (via Konnect).
#
# What it does:
#   1. installs ADOM from this checkout into a private venv
#   2. starts `adom kong-guard`, a capture proxy (records what Kong sends) and a mock model
#   3. uses Kong's official quickstart to create a Konnect control plane named "adom-smoke"
#      and run a local Kong Gateway data plane in Docker, licensed through Konnect
#   4. loads the config `adom kong-guard --emit-deck` generates (decK, run in Docker)
#   5. sends test traffic through Kong and prints PASS / FAIL / INFO
#   6. cleans up: stops local processes, removes the containers and the "adom-smoke"
#      control plane (set KEEP_KONG=1 to keep the gateway running afterwards)
#
# Needs: Docker Desktop running, Python 3.10+, curl, and a Konnect personal access token in
# ~/.adom/konnect-token (override with KONNECT_TOKEN_FILE). Region: KONNECT_REGION=us|eu|au|me|in
# (default us). Results and logs go to ~/.adom/kong-smoke (override with ADOM_KONG_WORK).
# The control plane name "adom-smoke" is deleted and recreated by Kong's quickstart, so it
# must not be one you use for anything else.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TOKEN_FILE="${KONNECT_TOKEN_FILE:-$HOME/.adom/konnect-token}"
REGION="${KONNECT_REGION:-us}"
CP_NAME="adom-smoke"
APP_NAME="adom-smoke"
WORK="${ADOM_KONG_WORK:-$HOME/.adom/kong-smoke}"
ADOM_PORT="${ADOM_PORT:-8780}"
GUARD_PORT="${GUARD_PORT:-8781}"
MOCK_PORT="${MOCK_PORT:-9100}"
# Docker Desktop for Mac reaches services on the Mac's 127.0.0.1 via host.docker.internal.
# If Kong cannot reach ADOM on your setup, rerun with BIND_HOST=0.0.0.0.
export BIND_HOST="${BIND_HOST:-127.0.0.1}"
DECK_IMAGE="${DECK_IMAGE:-kong/deck:latest}"
QUICKSTART_URL="https://get.konghq.com/quickstart"
PIDS=()

step() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  local code=$?
  set +e
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  if [ "${KEEP_KONG:-0}" != "1" ] && [ "${KONG_STARTED:-0}" = "1" ]; then
    step "Cleaning up: removing containers and the '$CP_NAME' control plane"
    curl -Ls "$QUICKSTART_URL" | KONNECT_REGION="$REGION" bash -s -- -d -k "$(cat "$TOKEN_FILE")" \
      -n "$CP_NAME" -a "$APP_NAME" > "$WORK/quickstart-destroy.log" 2>&1 \
      && echo "removed" || echo "cleanup had errors, see $WORK/quickstart-destroy.log"
  fi
  exit "$code"
}
trap cleanup EXIT

# ---- preflight -------------------------------------------------------------------------
step "Checking prerequisites"
command -v docker >/dev/null || die "Docker is not installed. Install Docker Desktop, start it, and rerun."
docker info >/dev/null 2>&1 || die "Docker is not running. Start Docker Desktop, wait for 'Engine running', and rerun."
command -v curl >/dev/null || die "curl is not installed."
[ -s "$TOKEN_FILE" ] || die "No Konnect token at $TOKEN_FILE. Generate one in Konnect (Personal access tokens) and save it there."
case "$REGION" in us|eu|au|me|in) ;; *) die "KONNECT_REGION must be one of us, eu, au, me, in (got '$REGION')";; esac

PY=""
for cand in python3.13 python3.12 python3.11 python3.10 python3; do
  if command -v "$cand" >/dev/null && "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    PY="$(command -v "$cand")"; break
  fi
done
[ -n "$PY" ] || die "Python 3.10+ not found (macOS's built-in python3 is 3.9). Install one, e.g. 'brew install python@3.12'."
echo "python: $PY ($("$PY" -V 2>&1))"

for port in "$ADOM_PORT" "$GUARD_PORT" "$MOCK_PORT"; do
  "$PY" -c "import socket,sys; s=socket.socket(); s.bind(('127.0.0.1', int(sys.argv[1])))" "$port" 2>/dev/null \
    || die "Port $port is in use. Free it or set ADOM_PORT / GUARD_PORT / MOCK_PORT."
done

mkdir -p "$WORK"
rm -f "$WORK"/*.jsonl "$WORK"/results.json "$WORK"/*.log

# ---- ADOM, capture proxy, mock model --------------------------------------------------
step "Installing ADOM from $ROOT into $WORK/venv"
"$PY" -m venv "$WORK/venv"
"$WORK/venv/bin/python" -m pip install -q --upgrade pip
"$WORK/venv/bin/python" -m pip install -q "$ROOT"
VPY="$WORK/venv/bin/python"

step "Starting ADOM guardrail (:$ADOM_PORT), capture proxy (:$GUARD_PORT) and mock model (:$MOCK_PORT)"
"$WORK/venv/bin/adom" kong-guard --bind 127.0.0.1 --port "$ADOM_PORT" \
  --allowed-tool read_ticket --approved-outbound corp.com \
  --audit-log "$WORK/decisions.jsonl" > "$WORK/adom.log" 2>&1 &
PIDS+=($!)
"$VPY" "$HERE/capture_proxy.py" "$GUARD_PORT" "$ADOM_PORT" "$WORK" > "$WORK/capture.log" 2>&1 &
PIDS+=($!)
"$VPY" "$HERE/mock_llm.py" "$MOCK_PORT" "$WORK" > "$WORK/mock.log" 2>&1 &
PIDS+=($!)
for i in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$GUARD_PORT/healthz" >/dev/null && curl -sf "http://127.0.0.1:$MOCK_PORT/" >/dev/null && break
  sleep 0.5
done
curl -sf "http://127.0.0.1:$GUARD_PORT/healthz" >/dev/null || die "ADOM guardrail did not start; see $WORK/adom.log"
echo "local services up"

# ---- Kong data plane via Konnect -------------------------------------------------------
step "Creating Konnect control plane '$CP_NAME' ($REGION) and a local Kong data plane (Kong quickstart)"
KONG_STARTED=1
curl -Ls "$QUICKSTART_URL" | KONNECT_REGION="$REGION" bash -s -- -k "$(cat "$TOKEN_FILE")" \
  -n "$CP_NAME" -a "$APP_NAME" -P > "$WORK/quickstart.log" 2>&1 \
  || die "Kong quickstart failed; see $WORK/quickstart.log"
GW="$APP_NAME-gateway"
docker inspect "$GW" >/dev/null 2>&1 || die "Kong gateway container '$GW' not found; see $WORK/quickstart.log"
PROXY_HOSTPORT="$(docker port "$GW" 8000/tcp | head -1 | sed 's/.*://')"
[ -n "$PROXY_HOSTPORT" ] || die "Could not find the gateway's proxy port; see $WORK/quickstart.log"
PROXY_URL="http://127.0.0.1:$PROXY_HOSTPORT"
echo "gateway: $(docker inspect -f '{{.Config.Image}}' "$GW"), proxy at $PROXY_URL"

# ---- load ADOM's generated Kong config --------------------------------------------------
step "Generating ADOM's decK config and syncing it to '$CP_NAME'"
"$VPY" "$HERE/prepare_deck.py" "$GUARD_PORT" "$MOCK_PORT" "$WORK/kong.yaml"
docker run --rm -v "$WORK:/work" -v "$TOKEN_FILE:/token:ro" \
  -e DECK_OPENAI_API_KEY="sk-test-not-a-real-key" "$DECK_IMAGE" \
  gateway sync /work/kong.yaml --konnect-token-file /token \
  --konnect-control-plane-name "$CP_NAME" --konnect-addr "https://$REGION.api.konghq.com" \
  > "$WORK/deck.log" 2>&1 \
  || { cat "$WORK/deck.log"; die "decK rejected the config (output above). That is a real finding: send it to Claude."; }
tail -3 "$WORK/deck.log"

# ---- traffic -------------------------------------------------------------------------------
step "Sending test traffic through Kong"
set +e
"$VPY" "$HERE/smoke.py" "$PROXY_URL" "$WORK"
RESULT=$?
set -e
echo
if [ "$RESULT" = 0 ]; then
  echo "SMOKE TEST PASSED. Copy everything from 'Sending test traffic' down and send it to Claude."
else
  echo "SMOKE TEST HAD FAILURES. Copy everything from 'Sending test traffic' down and send it to Claude."
fi
exit "$RESULT"
