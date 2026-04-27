"""
Aggregate every result file produced by the SoFuzz pipeline into a single
PPT-ready summary table.

Reads (whatever exists under results/):
  - seed_pool.json
  - seed_transfer_eval_*.csv / .json
  - seed_transfer_triage_*.csv / .json
  - coverage_guided_transfer_*.json
  - adaptive_budget_eval_*.csv / .json
  - adaptive_budget_triage_*.csv / .json
  - host_crash_triage_*.csv / .json

Writes:
  - results/_presentation/summary.txt
  - results/_presentation/summary.md
  - results/_presentation/seed_transfer_table.csv
  - results/_presentation/adaptive_table.csv
  - results/_presentation/coverage_guided_table.csv
  - results/_presentation/triage_table.csv

Run:
    python3 tools/collect_results.py
"""

import csv
import glob
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "results"
OUT = RESULTS / "_presentation"


def safe_load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception as exc:
        print(f"[WARN] could not read {path}: {exc}", file=sys.stderr)
        return None


def safe_load_csv(path):
    try:
        with open(path, newline="") as fp:
            return list(csv.DictReader(fp))
    except Exception as exc:
        print(f"[WARN] could not read {path}: {exc}", file=sys.stderr)
        return []


def latest(pattern):
    matches = sorted(glob.glob(str(RESULTS / pattern)))
    return matches[-1] if matches else None


def write_csv(path, rows):
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = list(rows[0].keys())
    with open(path, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def section_seed_pool():
    pool_path = RESULTS / "seed_pool.json"
    if not pool_path.exists():
        return "Seed pool: not built yet (run tools/build_seed_pool.py)\n"
    data = safe_load_json(pool_path) or {}
    keys = data.get("count_keys", len(data.get("pool", {})))
    harnesses = data.get("count_harnesses", len(data.get("entries", [])))
    pool = data.get("pool", {})
    sizes = sorted(((len(v), k) for k, v in pool.items()), reverse=True)[:5]
    lines = [
        "Seed Pool",
        "---------",
        f"  signature_keys:    {keys}",
        f"  total_harnesses:   {harnesses}",
        "  top-5 most-shared signature keys:",
    ]
    for size, key in sizes:
        lines.append(f"    {size:5d}  {key}")
    return "\n".join(lines) + "\n"


def section_seed_transfer():
    eval_csv = latest("seed_transfer_eval_*.csv")
    triage_csv = latest("seed_transfer_triage_*.csv")
    if not eval_csv:
        return "Seed Transfer Comparison: no run found\n"

    rows = safe_load_csv(eval_csv)
    by_method = {}
    for r in rows:
        m = r.get("method", "")
        by_method.setdefault(m, []).append(r)

    triage_rows = safe_load_csv(triage_csv) if triage_csv else []
    clusters_per_method = {}
    for tr in triage_rows:
        m = tr.get("method") or tr.get("group") or ""
        clusters_per_method.setdefault(m, set()).add(tr.get("signature", ""))

    table = []
    for method, mrows in by_method.items():
        execs = sum(int(r.get("executions") or 0) for r in mrows)
        crashes = sum(int(r.get("crashes") or 0) for r in mrows)
        secs = sum(float(r.get("duration_seconds") or 0) for r in mrows)
        unique = len(clusters_per_method.get(method, set())) or "n/a"
        table.append(
            {
                "method": method,
                "runs": len(mrows),
                "duration_seconds": int(secs),
                "executions": execs,
                "raw_crashes": crashes,
                "unique_clusters": unique,
                "execs_per_sec": round(execs / secs, 2) if secs else 0,
                "crashes_per_sec": round(crashes / secs, 2) if secs else 0,
            }
        )

    write_csv(OUT / "seed_transfer_table.csv", table)

    lines = [
        "Novelty 1 — Seed Transfer Comparison (eval CSV: %s)" % eval_csv,
        "----------------------------------------------------",
        f"{'method':<28} {'runs':>4} {'execs':>9} {'raw_cr':>7} {'uniq':>5} {'ex/s':>7} {'cr/s':>7}",
    ]
    for r in table:
        lines.append(
            f"{r['method']:<28} {r['runs']:>4} {r['executions']:>9} "
            f"{r['raw_crashes']:>7} {str(r['unique_clusters']):>5} "
            f"{r['execs_per_sec']:>7} {r['crashes_per_sec']:>7}"
        )
    return "\n".join(lines) + "\n"


def section_coverage_guided():
    files = sorted(glob.glob(str(RESULTS / "coverage_guided_transfer_*.json")))
    if not files:
        return "Coverage-Guided Transfer: no run found\n"

    rows = []
    for f in files:
        d = safe_load_json(f) or {}
        rows.append(
            {
                "file": os.path.basename(f),
                "app": d.get("app"),
                "harness": d.get("harness"),
                "candidates_probed": len(d.get("decisions", [])),
                "accepted": d.get("accepted", 0),
                "rejected_duplicate": d.get("rejected_duplicate", 0),
                "rejected_same_app": d.get("rejected_same_app", 0),
                "rejected_error": d.get("rejected_error", 0),
                "unique_baseline_fps": d.get("unique_baseline_fps", 0),
                "unique_total_fps": d.get("unique_total_fps", 0),
            }
        )
    write_csv(OUT / "coverage_guided_table.csv", rows)

    lines = [
        "Novelty 1b — Coverage-Guided Decisions",
        "--------------------------------------",
        f"{'app':<28} {'harness':<32} {'probed':>7} {'accept':>7} {'dup':>5} {'sameapp':>8} {'err':>5}",
    ]
    for r in rows:
        lines.append(
            f"{(r['app'] or '')[:28]:<28} {(r['harness'] or '')[:32]:<32} "
            f"{r['candidates_probed']:>7} {r['accepted']:>7} "
            f"{r['rejected_duplicate']:>5} {r['rejected_same_app']:>8} {r['rejected_error']:>5}"
        )
    return "\n".join(lines) + "\n"


def section_adaptive():
    eval_json = latest("adaptive_budget_eval_*.json")
    if not eval_json:
        return "Adaptive Top-K: no run found\n"
    d = safe_load_json(eval_json) or {}
    summary = d.get("summary", {})
    rows = d.get("rows", [])

    table = [
        {
            "strategy": "baseline",
            "selected": ", ".join(summary.get("baseline_selected", [])),
            "runs": summary.get("baseline_full", {}).get("runs", 0),
            "total_executions": summary.get("baseline_full", {}).get("total_executions", 0),
            "total_crashes": summary.get("baseline_full", {}).get("total_crashes", 0),
        },
        {
            "strategy": "adaptive",
            "selected": ", ".join(summary.get("adaptive_selected", [])),
            "runs": summary.get("adaptive_full", {}).get("runs", 0),
            "total_executions": summary.get("adaptive_full", {}).get("total_executions", 0),
            "total_crashes": summary.get("adaptive_full", {}).get("total_crashes", 0),
        },
    ]
    write_csv(OUT / "adaptive_table.csv", table)

    pilot_rows = [r for r in rows if r.get("phase") == "pilot"]
    pilot_rows.sort(key=lambda r: float(r.get("score") or 0), reverse=True)

    lines = [
        "Novelty 2 — Adaptive Top-K Harness Budgeting (eval JSON: %s)" % eval_json,
        "------------------------------------------------------------",
        f"  app:              {summary.get('app')}",
        f"  candidate_limit:  {summary.get('candidate_limit')}",
        f"  top_k:            {summary.get('top_k')}",
        f"  pilot_time:       {summary.get('pilot_time')}s",
        f"  full_time:        {summary.get('full_time')}s",
        "",
        f"  baseline_selected: {table[0]['selected']}",
        f"  adaptive_selected: {table[1]['selected']}",
        "",
        f"  {'strategy':<10} {'runs':>4} {'execs':>9} {'crashes':>8}",
    ]
    for r in table:
        lines.append(
            f"  {r['strategy']:<10} {r['runs']:>4} "
            f"{r['total_executions']:>9} {r['total_crashes']:>8}"
        )
    if pilot_rows:
        lines += ["", "  Pilot scoreboard (top 5):", f"  {'rank':>4} {'score':>7} {'crashes':>8} {'execs':>8}  harness"]
        for i, r in enumerate(pilot_rows[:5], 1):
            lines.append(
                f"  {i:>4} {float(r.get('score') or 0):>7.2f} "
                f"{int(r.get('crashes') or 0):>8} "
                f"{int(r.get('executions') or 0):>8}  {r.get('harness')}"
            )
    return "\n".join(lines) + "\n"


def section_triage():
    files = sorted(glob.glob(str(RESULTS / "*triage*.csv")))
    if not files:
        return "Triage: no triage CSV found\n"
    rows = []
    for f in files:
        data = safe_load_csv(f)
        rows.append(
            {
                "file": os.path.basename(f),
                "rows_in_csv": len(data),
                "unique_signatures": len({r.get("signature", "") for r in data}),
                "unique_apps": len({r.get("app", "") for r in data if r.get("app")}),
                "unique_harnesses": len({r.get("harness", "") for r in data if r.get("harness")}),
            }
        )
    write_csv(OUT / "triage_table.csv", rows)
    lines = [
        "Novelty 3 — Crash Triage",
        "------------------------",
        f"{'file':<55} {'rows':>5} {'uniq_sig':>9} {'apps':>5} {'harn':>5}",
    ]
    for r in rows:
        lines.append(
            f"{r['file']:<55} {r['rows_in_csv']:>5} "
            f"{r['unique_signatures']:>9} {r['unique_apps']:>5} {r['unique_harnesses']:>5}"
        )
    return "\n".join(lines) + "\n"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sections = [
        section_seed_pool(),
        section_seed_transfer(),
        section_coverage_guided(),
        section_adaptive(),
        section_triage(),
    ]
    txt = "\n".join(sections)
    (OUT / "summary.txt").write_text(txt)
    (OUT / "summary.md").write_text("```\n" + txt + "\n```\n")

    print(txt)
    print(f"\n[OK] presentation artifacts in: {OUT}")


if __name__ == "__main__":
    main()
