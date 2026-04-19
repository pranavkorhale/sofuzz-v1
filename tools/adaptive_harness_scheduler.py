import argparse
import csv
import json
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
HOST_FUZZ = REPO_ROOT / "fuzzing" / "host_fuzz.py"
DEFAULT_DB = REPO_ROOT / "fuzzing" / "fuzz.db"
TRIAGE_TOOL = REPO_ROOT / "tools" / "triage_host_crashes.py"


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
            f"host_fuzz failed for harness={harness} seed_source={seed_source}\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )

    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    for i in range(len(lines)):
        try:
            return json.loads("\n".join(lines[i:]))
        except json.JSONDecodeError:
            continue
    raise RuntimeError(
        "host_fuzz finished but JSON summary could not be parsed.\n"
        f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
    )


def load_harnesses(db_path, app, candidate_limit):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    rows = cur.execute(
        "SELECT fname FROM fuzzdata WHERE app = ? ORDER BY rowid LIMIT ?",
        (app, candidate_limit),
    ).fetchall()
    cur.close()
    con.close()
    return [row[0] for row in rows]


def score_summary(summary):
    crashes = int(summary.get("crashes", 0) or 0)
    execs = int(summary.get("executions", 0) or 0)
    parse_rate = summary.get("seed_parse_success_rate")
    if parse_rate is None:
        parse_rate = 0.0
    # Crashes dominate; execs and parser stability break ties.
    return crashes + (execs * 0.001) + (parse_rate * 0.1)


def flatten_row(run_id, strategy, phase, app, harness, rank, score, summary):
    return {
        "run_id": run_id,
        "strategy": strategy,
        "phase": phase,
        "app": app,
        "harness": harness,
        "rank": rank,
        "score": score,
        "duration_seconds": summary.get("duration_seconds"),
        "seed_source": summary.get("seed_source"),
        "executions": summary.get("executions"),
        "crashes": summary.get("crashes"),
        "selected_seed_files": summary.get("seed_stats", {}).get("selected_seed_files"),
        "local_seed_files": summary.get("seed_stats", {}).get("local_seed_files"),
        "transfer_seed_files": summary.get("seed_stats", {}).get("transfer_seed_files"),
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


def aggregate(rows, strategy, phase):
    chosen = [r for r in rows if r["strategy"] == strategy and r["phase"] == phase]
    return {
        "runs": len(chosen),
        "total_crashes": sum(int(r["crashes"] or 0) for r in chosen),
        "total_executions": sum(int(r["executions"] or 0) for r in chosen),
    }


def run_triage(rows, out_dir, run_id):
    output_dirs = [r["output_dir"] for r in rows if r["phase"] == "full" and r.get("output_dir")]
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
            f"adaptive_budget_triage_{run_id}",
        ]
    )
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        print(
            "[ADAPTIVE] triage failed (continuing):\n"
            f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )
        return
    print(proc.stdout.strip())


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Adaptive harness budgeting: pilot score harnesses, "
            "then compare baseline queue order vs adaptive top-K."
        )
    )
    parser.add_argument("--app", required=True, help="App name under target_APK")
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB),
        help="Path to fuzz queue database (default: fuzzing/fuzz.db)",
    )
    parser.add_argument(
        "--candidate-limit",
        type=int,
        default=10,
        help="Number of queue-order harnesses to consider for pilot (default: 10)",
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=3,
        help="Number of harnesses for full-budget comparison (default: 3)",
    )
    parser.add_argument(
        "--pilot-time",
        type=int,
        default=20,
        help="Pilot fuzz time per harness in seconds (default: 20)",
    )
    parser.add_argument(
        "--full-time",
        type=int,
        default=120,
        help="Full-budget fuzz time per harness in seconds (default: 120)",
    )
    parser.add_argument(
        "--seed-source",
        choices=["local", "transfer", "local+transfer"],
        default="local+transfer",
        help="Seed source passed to host_fuzz (default: local+transfer)",
    )
    parser.add_argument(
        "--out-dir",
        default=str(REPO_ROOT / "results"),
        help="Output directory for CSV/JSON artifacts",
    )
    args = parser.parse_args()

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    db_path = Path(args.db).resolve()
    out_dir = Path(args.out_dir).resolve()
    rows = []

    harnesses = load_harnesses(db_path=db_path, app=args.app, candidate_limit=args.candidate_limit)
    if not harnesses:
        raise RuntimeError(f"No harnesses found in DB for app={args.app}")

    print(f"[ADAPTIVE] candidates={len(harnesses)} app={args.app}")
    pilot_scores = []
    for idx, harness in enumerate(harnesses):
        print(f"[ADAPTIVE] pilot {idx + 1}/{len(harnesses)} harness={harness}")
        summary = run_host_fuzz(args.app, harness, args.pilot_time, args.seed_source)
        score = score_summary(summary)
        pilot_scores.append((harness, score, summary))
        rows.append(
            flatten_row(
                run_id=run_id,
                strategy="adaptive",
                phase="pilot",
                app=args.app,
                harness=harness,
                rank=None,
                score=score,
                summary=summary,
            )
        )

    ranked = sorted(pilot_scores, key=lambda item: item[1], reverse=True)
    adaptive_selected = [item[0] for item in ranked[: args.top_k]]
    baseline_selected = harnesses[: args.top_k]

    print(f"[ADAPTIVE] baseline_selected={baseline_selected}")
    print(f"[ADAPTIVE] adaptive_selected={adaptive_selected}")

    for rank, harness in enumerate(baseline_selected, start=1):
        print(f"[ADAPTIVE] baseline full rank={rank} harness={harness}")
        summary = run_host_fuzz(args.app, harness, args.full_time, args.seed_source)
        rows.append(
            flatten_row(
                run_id=run_id,
                strategy="baseline",
                phase="full",
                app=args.app,
                harness=harness,
                rank=rank,
                score=None,
                summary=summary,
            )
        )

    pilot_score_map = {harness: score for harness, score, _ in ranked}
    for rank, harness in enumerate(adaptive_selected, start=1):
        print(f"[ADAPTIVE] adaptive full rank={rank} harness={harness}")
        summary = run_host_fuzz(args.app, harness, args.full_time, args.seed_source)
        rows.append(
            flatten_row(
                run_id=run_id,
                strategy="adaptive",
                phase="full",
                app=args.app,
                harness=harness,
                rank=rank,
                score=pilot_score_map.get(harness),
                summary=summary,
            )
        )

    summary = {
        "run_id": run_id,
        "app": args.app,
        "seed_source": args.seed_source,
        "candidate_limit": args.candidate_limit,
        "top_k": args.top_k,
        "pilot_time": args.pilot_time,
        "full_time": args.full_time,
        "baseline_full": aggregate(rows, strategy="baseline", phase="full"),
        "adaptive_full": aggregate(rows, strategy="adaptive", phase="full"),
        "baseline_selected": baseline_selected,
        "adaptive_selected": adaptive_selected,
    }

    csv_path = out_dir / f"adaptive_budget_eval_{run_id}.csv"
    json_path = out_dir / f"adaptive_budget_eval_{run_id}.json"
    write_csv(rows, csv_path)
    json_path.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2))
    run_triage(rows=rows, out_dir=out_dir, run_id=run_id)

    print(f"[ADAPTIVE] wrote CSV: {csv_path}")
    print(f"[ADAPTIVE] wrote JSON: {json_path}")
    print("[ADAPTIVE] comparison")
    print(
        json.dumps(
            {
                "baseline_total_crashes": summary["baseline_full"]["total_crashes"],
                "adaptive_total_crashes": summary["adaptive_full"]["total_crashes"],
                "baseline_total_executions": summary["baseline_full"]["total_executions"],
                "adaptive_total_executions": summary["adaptive_full"]["total_executions"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
