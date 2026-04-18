#!/bin/bash

set -euo pipefail

# One-shot experiment runner for Ubuntu/Linux.
# Runs static pipeline, generates seed-constraint reports, and fuzzes one harness per app.

APKS_FILE="${APKS_FILE:-$(pwd)/apks.txt}"
FUZZ_TIME="${FUZZ_TIME:-180}"
MAX_APPS="${MAX_APPS:-5}"
RESULTS_DIR="${RESULTS_DIR:-$(pwd)/results/ubuntu_experiment_$(date +%Y%m%d_%H%M%S)}"

mkdir -p "${RESULTS_DIR}"
mkdir -p "${RESULTS_DIR}/logs"

if [ ! -f "${APKS_FILE}" ]; then
  echo "[RUN] APKS file not found: ${APKS_FILE}"
  exit 1
fi

export APKS="${APKS_FILE}"

echo "[RUN] APKS file: ${APKS_FILE}" | tee "${RESULTS_DIR}/logs/run.log"
echo "[RUN] MAX_APPS=${MAX_APPS} FUZZ_TIME=${FUZZ_TIME}s" | tee -a "${RESULTS_DIR}/logs/run.log"

echo "[RUN] Step 1/4: static pipeline" | tee -a "${RESULTS_DIR}/logs/run.log"
./run-static-pipeline.sh | tee "${RESULTS_DIR}/logs/static_pipeline.log"

echo "[RUN] Step 2/4: seed-constraint summary" | tee -a "${RESULTS_DIR}/logs/run.log"
python3 tools/print_seed_constraints.py --json-out "${RESULTS_DIR}/seed_constraints_summary.json" \
  | tee "${RESULTS_DIR}/logs/seed_constraints.log"

if [ ! -f "fuzzing/fuzz.db" ]; then
  echo "[RUN] fuzzing/fuzz.db not found after static pipeline"
  exit 1
fi

echo "[RUN] Step 3/4: selecting one harness per app" | tee -a "${RESULTS_DIR}/logs/run.log"
python3 - <<'PY' > "${RESULTS_DIR}/selected_targets.txt"
import os
import sqlite3

apks_path = os.environ["APKS"]
max_apps = int(os.environ.get("MAX_APPS", "5"))
selected_apps = []
for line in open(apks_path, "r"):
    app = line.strip()
    if app:
        selected_apps.append(app)
selected_apps = selected_apps[:max_apps]

con = sqlite3.connect("fuzzing/fuzz.db")
cur = con.cursor()
for app in selected_apps:
    row = cur.execute(
        "SELECT fname FROM fuzzdata WHERE app = ? ORDER BY fname LIMIT 1", (app,)
    ).fetchone()
    if row is None:
        continue
    print(f"{app}|{row[0]}")
cur.close()
con.close()
PY

if [ ! -s "${RESULTS_DIR}/selected_targets.txt" ]; then
  echo "[RUN] no app/harness pairs found in fuzz.db"
  exit 1
fi

cat "${RESULTS_DIR}/selected_targets.txt" | tee "${RESULTS_DIR}/logs/selected_targets.log"

echo "[RUN] Step 4/4: host fuzzing" | tee -a "${RESULTS_DIR}/logs/run.log"
while IFS='|' read -r app harness; do
  [ -z "${app}" ] && continue
  [ -z "${harness}" ] && continue
  echo "[RUN] fuzzing app=${app} harness=${harness}" | tee -a "${RESULTS_DIR}/logs/run.log"
  ./run_host_fuzz.sh "${app}" "${harness}" "${FUZZ_TIME}" \
    | tee "${RESULTS_DIR}/logs/host_fuzz_${app}.log"
done < "${RESULTS_DIR}/selected_targets.txt"

echo "[RUN] finished. results saved to: ${RESULTS_DIR}" | tee -a "${RESULTS_DIR}/logs/run.log"
