#!/bin/bash

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "Usage: ./run_host_fuzz.sh <APPNAME> <HARNESS_NAME> [TIME_SECONDS] [SEED_SOURCE]"
  echo "SEED_SOURCE: local | transfer | local+transfer (default: local)"
  exit 1
fi

APP="$1"
HARNESS="$2"
TIME_SECONDS="${3:-300}"
SEED_SOURCE="${4:-local}"

python3 fuzzing/host_fuzz.py --target "$APP" --target_function "$HARNESS" -t "$TIME_SECONDS" --seed-source "$SEED_SOURCE" --rebuild
