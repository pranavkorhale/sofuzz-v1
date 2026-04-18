#!/bin/bash

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "Usage: ./run_host_fuzz.sh <APPNAME> <HARNESS_NAME> [TIME_SECONDS]"
  exit 1
fi

APP="$1"
HARNESS="$2"
TIME_SECONDS="${3:-300}"

python3 fuzzing/host_fuzz.py --target "$APP" --target_function "$HARNESS" -t "$TIME_SECONDS" --rebuild
