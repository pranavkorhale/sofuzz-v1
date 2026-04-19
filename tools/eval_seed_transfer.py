"""
Evaluate seed transfer strategies on a single harness.

Supported methods (comma-separated via --methods):
  baseline                    -> seed_source=local, no transfer applied
  naive_transfer              -> apply_seed_transfer.py then seed_source=local+transfer
  coverage_guided_transfer    -> coverage_guided_transfer.py then seed_source=local+transfer

Outputs:
  - results/seed_transfer_eval_<run_id>.csv
  - results/seed_transfer_eval_<run_id>.json
  - results/seed_transfer_triage_<run_id>.{csv,json} (auto crash triage)
"""

import argparse
import csv
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
HOST_FUZZ = REPO_ROOT / "fuzzing" / "host_fuzz.py"
TRIAGE_TOOL = REPO_ROOT / "tools" / "triage_host_crashes.py"
APPLY_TRANSFER_TOOL = REPO_ROOT / "tools" / "apply_seed_transfer.py"
COVERAGE_GUIDED_TOOL = REPO_ROOT / "tools" / "coverage_guided_transfer.py"


METHOD_DEFS = {
    "baseline": {"seed_source": "local"},
    "naive_transfer": {"seed_source": "local+transfer"},
    "coverage_guided_transfer": {"seed_source": "local+transfer"},
}


def parse_json_from_stdout(stdout, stderr):
    lines = [line for line in stdout.splitlines() if line.strip()]
    for i in range(len(lines)):
        candidate = "\n".join(lines[i:])
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise RuntimeError(
        f"Could not parse JSON summary from subprocess output.\n"
        f"stdout:\n{stdout}\n\nstderr:\n{stderr}"
    )


def run_subprocess(cmd, why):
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"{why} failed (rc={proc.returncode})\n"
            f"cmd: {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )
    return proc


def reset_transfer_dir(app, harness):
    transfer_dir = REPO_ROOT / "target_APK" / app / "harnesses" / harness / "seeds_transfer"
    if transfer_dir.exists():
        shutil.rmtree(transfer_dir)


def apply_naive_transfer(app, harness):
    cmd = [
        "python3",
        str(APPLY_TRANSFER_TOOL),
        "--app",
        app,
        "--harness",
        harness,
        "--clean",
    ]
    run_subprocess(cmd, "apply_seed_transfer")


def apply_coverage_guided_transfer(app, harness):
    cmd = [
        "python3",
        str(COVERAGE_GUIDED_TOOL),
        "--app",
        app,
        "--harness",
        harness,
        "--clean",
    ]
    run_subprocess(cmd, "coverage_guided_transfer")


def run_host_fuzz(app, harness, seconds, seed_source):
    cmd = [
        "python3",
        str(HOST_FUZZ),
        "--target",
        app,
        "--target_function",
        harness,
        "-t",
        str(seconds),
        "--seed-source",
        seed_source,
        "--rebuild",
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"host_fuzz failed for seed_source={seed_source}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )
    return parse_json_from_stdout(proc.stdout, proc.stderr)


def setup_method(method, app, harness):
    if method == "baseline":
        reset_transfer_dir(app, harness)
        return
    if method == "naive_transfer":
        apply_naive_transfer(app, harness)
        return
    if method == "coverage_guided_transfer":
        apply_coverage_guided_transfer(app, harness)
        return
    raise SystemExit(f"unknown method: {method}")


def flatten_summary(run_id, app, harness, method, summary):
    return {
        "run_id": run_id,
        "app": app,
        "harness": harness,
        "method": method,
        "duration_seconds": summary.get("duration_seconds"),
        "executions": summary.get("executions"),
        "crashes": summary.get("crashes"),
        "seed_source": summary.get("seed_source"),
        "selected_seed_files": summary.get("seed_stats", {}).get("selected_seed_files"),
        "local_seed_files": summary.get("seed_stats", {}).get("local_seed_files"),
        "transfer_seed_files": summary.get("seed_stats", {}).get("transfer_seed_files"),
        "mutation_mode": summary.get("mutation_mode"),
        "structured_mutations": summary.get("structured_mutations"),
        "seed_parse_attempts": summary.get("seed_parse_attempts"),
        "seed_parse_successes": summary.get("seed_parse_successes"),
        "seed_parse_success_rate": summary.get("seed_parse_success_rate"),
        "output_dir": summary.get("output_dir"),
    }


def write_csv(rows, out_csv):
    if not rows:
        return
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def run_triage(output_dirs, out_dir, run_id):
    output_dirs = [d for d in output_dirs if d]
    if not output_dirs:
        return
    cmd = ["python3", str(TRIAGE_TOOL)]
    for output_dir in output_dirs:
        cmd.extend(["--input-dir", output_dir])
    cmd.extend(
        [
            "--out-dir",
            str(out_dir),
            "--out-prefix",
            f"seed_transfer_triage_{run_id}",
        ]
    )
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        print(
            "[EVAL] triage failed (continuing):\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )
        return
    print(proc.stdout.strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, help="Target app under target_APK")
    parser.add_argument("--harness", required=True, help="Harness folder name")
    parser.add_argument(
        "--time",
        type=int,
        default=120,
        help="Fuzz time per method in seconds (default: 120)",
    )
    parser.add_argument(
        "--methods",
        default="baseline,naive_transfer,coverage_guided_transfer",
        help=(
            "Comma-separated methods to run "
            "(default: baseline,naive_transfer,coverage_guided_transfer)"
        ),
    )
    parser.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "results"),
        help="Output directory for comparison artifacts (default: results/)",
    )
    args = parser.parse_args()

    methods = [m.strip() for m in args.methods.split(",") if m.strip()]
    for m in methods:
        if m not in METHOD_DEFS:
            raise SystemExit(f"unknown method '{m}'. valid: {list(METHOD_DEFS)}")

    out_dir = Path(args.out_dir).resolve()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    rows = []
    output_dirs = []
    summaries = {}

    for method in methods:
        print(f"[EVAL] setting up method={method}")
        setup_method(method, args.app, args.harness)
        seed_source = METHOD_DEFS[method]["seed_source"]
        print(f"[EVAL] running method={method} seed_source={seed_source}")
        summary = run_host_fuzz(args.app, args.harness, args.time, seed_source)
        summaries[method] = summary
        rows.append(flatten_summary(run_id, args.app, args.harness, method, summary))
        output_dirs.append(summary.get("output_dir"))

    csv_path = out_dir / f"seed_transfer_eval_{run_id}.csv"
    json_path = out_dir / f"seed_transfer_eval_{run_id}.json"
    write_csv(rows, csv_path)
    json_path.write_text(json.dumps({"rows": rows}, indent=2))

    run_triage(output_dirs=output_dirs, out_dir=out_dir, run_id=run_id)

    print(f"[EVAL] wrote CSV: {csv_path}")
    print(f"[EVAL] wrote JSON: {json_path}")
    print("[EVAL] quick comparison")
    print(
        json.dumps(
            {
                method: {
                    "executions": summaries[method].get("executions"),
                    "crashes": summaries[method].get("crashes"),
                    "transfer_seed_files": summaries[method]
                    .get("seed_stats", {})
                    .get("transfer_seed_files"),
                }
                for method in methods
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
