#!/bin/bash

export APKS="$(pwd)/apks.txt"
# export CLEAN=1

export SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export FUZZ_DATA="${SCRIPT_DIR}/$(date +%s)_fuzzing_data"

rm -rf "${FUZZ_DATA}"
mkdir "${FUZZ_DATA}"

rm -rf target_APK/*/harnesses/*
python3 run_static_analysis_batch.py

# Generate harnesses with different strategy combinations.
export HARNESS_GEN_FLAGS="-jo_ok -cs_ph -cs_io -cs_ph_min_len 1 -ct_argval -fuzz --afl_coverage_on"
python3 generate_harnesses_batch.py
export HARNESS_GEN_FLAGS="-jo_ok -cs_ph -cs_io -cs_ph_min_len 1 -fuzz --afl_coverage_on"
python3 generate_harnesses_batch.py
export HARNESS_GEN_FLAGS="-jo_ok -ct_argval -fuzz --afl_coverage_on"
python3 generate_harnesses_batch.py
export HARNESS_GEN_FLAGS="-jo_ok -fuzz --afl_coverage_on"
python3 generate_harnesses_batch.py

export APP2FNAMES="${FUZZ_DATA}/app2fnames.json"
python3 build_fuzz_queue.py
cp fuzzing/fuzz.db "${FUZZ_DATA}/" 2>/dev/null || true

echo "[STATIC] Static-only pipeline completed."
