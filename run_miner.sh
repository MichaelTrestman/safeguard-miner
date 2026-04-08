#!/usr/bin/env bash
# safeguard-miner launcher. Activates the bittensor venv (shared with the
# rest of latents/) and runs miner.py.
set -euo pipefail

cd "$(dirname "$0")"

VENV="${VENV:-../bittensor/venv}"
if [[ -f "$VENV/bin/activate" ]]; then
  # shellcheck disable=SC1091
  source "$VENV/bin/activate"
else
  echo "venv not found at $VENV — set VENV env var or activate manually" >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  echo ".env missing — copy env.example to .env and fill in CHUTES_API_KEY" >&2
  exit 1
fi

exec python miner.py 2>&1 | tee -a miner.log
