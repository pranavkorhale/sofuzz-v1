import argparse
import csv
import json
import subprocess
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
HOST_FUZZ = REPO_ROOT / "fuzzing" / "host_fuzz.py"


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
    summary = json.loads(proc.stdout)
    return summary


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


def main():
    parser = argparse.ArgumentParser(
        description="Run baseline vs transfer host fuzz and write comparison outputs."
    )
    parser.add_argument("--app", required=True, help="Target app under target_APK")
    parser.add_argument("--harness", required=True, help="Harness folder name")
    parser.add_argument(
        "--time",
        type=int,
        default=120,
        help="Fuzz time per method in seconds (default: 120)",
    )
    parser.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "results"),
        help="Output directory for comparison artifacts (default: results/)",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    run_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    print("[EVAL] running baseline (local seeds)")
    baseline = run_host_fuzz(args.app, args.harness, args.time, "local")
    print("[EVAL] running transfer (local+transfer seeds)")
    transfer = run_host_fuzz(args.app, args.harness, args.time, "local+transfer")

    rows = [
        flatten_summary(run_id, args.app, args.harness, "baseline_local", baseline),
        flatten_summary(run_id, args.app, args.harness, "transfer_local_plus_transfer", transfer),
    ]
    csv_path = out_dir / f"seed_transfer_eval_{run_id}.csv"
    json_path = out_dir / f"seed_transfer_eval_{run_id}.json"
    write_csv(rows, csv_path)
    json_path.write_text(json.dumps({"rows": rows}, indent=2))

    print(f"[EVAL] wrote CSV: {csv_path}")
    print(f"[EVAL] wrote JSON: {json_path}")
    print("[EVAL] quick comparison")
    print(
        json.dumps(
            {
                "baseline_crashes": baseline.get("crashes"),
                "transfer_crashes": transfer.get("crashes"),
                "baseline_execs": baseline.get("executions"),
                "transfer_execs": transfer.get("executions"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
