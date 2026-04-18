# SoFuzz

Framework to fuzz native libraries of an Android app

# Requirements

This repository now supports a **static-only pipeline** that does not require emulator/ADB setup.
The dynamic runtime fuzzing pipeline has been removed from this repository.

For the artifact evaluation we ran SoFuzz on an arm64 machine with the 
NXP Lay-erscape LX2160A CPU.

# Setup

Build the docker:
```
./setup.sh
```

Spawn a shell in the docker (all following commands assume you are in the docker container shell)

```
./run.sh
```

## Preparation

### Target Collection

Populate the target_APK folder with the APKs. The structure should be the following:
```
 target_APK/
 ├── APPNAME/
    └── base.apk
```

## Static Analysis (default)

### Argument Value Analysis And JNI Function Offsets

Extract the static information (argument value pass and JNI signatures) 
for a specific app in the **target_APK/** folder:

```
python3 static_analysis/preprocess.py --target [APPNAME] --static_only
```

For more options check the README in **static_analysis/**

After this step the following files should be present (for apps with native functions)

```
 target_APK/
 ├── APPNAME/
    └── base.apk
    └── static_analysis/
    └── lib/
    └── signatures_pattern.txt
    └── signatures_libraries_offsets.txt (optional in static-only mode)
```

### Call Sequence Pass

**TODO** 

## Generate Harnesses

With the information on the function signatures, harnesses for these functions can be generated using the script **harness/harness_generator.py**.

Generate harness for a specific app in **target_APK/**:

```
python3 harness/harness_generator.py --target [APPNAME]
```
Note that the harness generator has a number of options, check the `run-static-pipeline.sh` script to see which flags were used.

After this step, the following folder structure should be in place. Now all the necessary information for fuzzing is now present.

```
 target_APK/
 ├── APPNAME/
    └── base.apk
    └── static_analysis/
    └── lib/
    └── signatures_pattern.txt
    └── signatures_libraries_offsets.txt
    └── harnesses/
        └── fname-signature@cs_number-io_matching_possibility/
            └── harness.cpp
            └── harness_debug.cpp
            └── seeds/ (folder with seeds with the correct input byte structure)
```

## Static-Only End-to-End Run

Run the full static-only orchestration (analysis + harness generation + queueing):

```
./run-static-pipeline.sh
```

This is now the supported workflow for this repository.

## Host Native Fuzzing (No Device)

After static analysis + harness generation, you can run host-side fuzzing directly on the native `.so` target:

```bash
python3 fuzzing/host_fuzz.py --target [APPNAME] --target_function [HARNESS_NAME] -t 300 --rebuild
```

Or use the wrapper:

```bash
./run_host_fuzz.sh [APPNAME] [HARNESS_NAME] 300
```

Output is written to:

```
target_APK/[APPNAME]/fuzzing_output_host/[HARNESS_NAME]/output_host_[TIMESTAMP]/
```

Notes:
- This mode does not use emulator/adb orchestration.
- It requires local toolchain/runtime dependencies (`g++`, Java/JNI headers via `JAVA_HOME`).
- Some targets may additionally require Android runtime shared libraries (`libart.so`, `libandroid_runtime.so`) available in the loader path.

## Ubuntu One-Shot Experiment

To run a quick end-to-end experiment on Ubuntu/Linux:

```bash
./run_ubuntu_experiment.sh
```

Optional environment overrides:

```bash
APKS_FILE=/path/to/apks.txt MAX_APPS=5 FUZZ_TIME=180 ./run_ubuntu_experiment.sh
```

This script runs:
- static pipeline (`run-static-pipeline.sh`)
- seed constraint reporting (`tools/print_seed_constraints.py`)
- host fuzzing for one harness per selected app

Results are stored in `results/ubuntu_experiment_<timestamp>/`.

## Seed Constraint Reporting

After harness generation, each harness contains `seed_constraints.json`.
You can summarize these artifacts with:

```bash
python3 tools/print_seed_constraints.py
```

Filter by app/harness:

```bash
python3 tools/print_seed_constraints.py --app [APPNAME] --harness [HARNESS_NAME]
```

Export summary JSON:

```bash
python3 tools/print_seed_constraints.py --json-out results/seed_constraints_summary.json
```

## Components

```
.
├── fuzzing/lib/
├── harness/
├── static_analysis/
├── target_APK/
├── ghidra/
└── README.md
```

* **/fuzzing/lib**: sqlite/db helper modules used by static queueing scripts
* **/harness**: harness/seed generation and compilation scripts
* **/static_analysis**: code to statically anaylze the apks, extract native function signatures corresponding library and the offset
* **/target_APK**: contains all the downloaded/analyzed apks, the generated harnesses/seeds and fuzzing output
* **ghidra**: ghidra scripts to get insights into jni native libraries
* **README.md**: this README
