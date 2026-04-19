import argparse
import csv
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_APK = REPO_ROOT / "target_APK"
DEFAULT_OUT_DIR = REPO_ROOT / "results"

HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
LONG_NUM_RE = re.compile(r"\b\d{5,}\b")


def normalize_line(line):
    out = line.strip()
    if not out:
        return out
    out = HEX_RE.sub("0xADDR", out)
    out = LONG_NUM_RE.sub("NUM", out)
    return out


def discover_stderr_files(input_dirs, app=None, harness=None):
    stderr_paths = []
    if input_dirs:
        for d in input_dirs:
            root = Path(d).resolve()
            if not root.exists():
                continue
            stderr_paths.extend(sorted(root.glob("logs/*.stderr.txt")))
        return stderr_paths

    if app and harness:
        base = TARGET_APK / app / "fuzzing_output_host" / harness
        return sorted(base.glob("output_host_*/logs/*.stderr.txt"))
    if app:
        base = TARGET_APK / app / "fuzzing_output_host"
        return sorted(base.glob("*/output_host_*/logs/*.stderr.txt"))
    return sorted(TARGET_APK.glob("*/fuzzing_output_host/*/output_host_*/logs/*.stderr.txt"))


def extract_signal_from_name(path):
    # Example: id_000123_signal_SIGABRT.bin.stderr.txt
    name = path.name
    if "_signal_" in name:
        part = name.split("_signal_", 1)[1]
        return part.split(".", 1)[0]
    if "_exit_" in name:
        part = name.split("_exit_", 1)[1]
        return "exit_" + part.split(".", 1)[0]
    return "unknown"


def crash_signature(stderr_text, signal_kind, max_lines):
    lines = [normalize_line(line) for line in stderr_text.splitlines() if line.strip()]
    if not lines:
        return f"{signal_kind}|<empty>"
    head = lines[:max_lines]
    return f"{signal_kind}|{' || '.join(head)}"


def parse_stderr_entry(path, max_sig_lines):
    text = path.read_text(errors="replace")
    signal_kind = extract_signal_from_name(path)
    signature = crash_signature(text, signal_kind=signal_kind, max_lines=max_sig_lines)
    parts = path.parts
    # .../target_APK/<app>/fuzzing_output_host/<harness>/output_host_x/logs/file.stderr.txt
    app = parts[-6] if len(parts) >= 6 else "unknown_app"
    harness = parts[-4] if len(parts) >= 4 else "unknown_harness"
    run_dir = str(path.parent.parent)
    return {
        "app": app,
        "harness": harness,
        "signal": signal_kind,
        "signature": signature,
        "stderr_path": str(path),
        "run_dir": run_dir,
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
        description="Cluster host fuzz crashes by normalized stderr signatures."
    )
    parser.add_argument("--app", help="Optional app filter under target_APK")
    parser.add_argument("--harness", help="Optional harness filter (requires --app)")
    parser.add_argument(
        "--input-dir",
        action="append",
        default=[],
        help="Optional output_host_* directory to triage. Can be passed multiple times.",
    )
    parser.add_argument(
        "--max-sig-lines",
        type=int,
        default=3,
        help="Max stderr lines per signature (default: 3)",
    )
    parser.add_argument(
        "--sample-per-cluster",
        type=int,
        default=3,
        help="Number of sample crash files per cluster (default: 3)",
    )
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Output directory for triage artifacts (default: results/)",
    )
    parser.add_argument(
        "--out-prefix",
        default="host_crash_triage",
        help="Output filename prefix (default: host_crash_triage)",
    )
    args = parser.parse_args()

    if args.harness and not args.app:
        raise SystemExit("--harness requires --app")

    stderr_files = discover_stderr_files(
        input_dirs=args.input_dir, app=args.app, harness=args.harness
    )
    entries = [parse_stderr_entry(path, args.max_sig_lines) for path in stderr_files]

    clusters = defaultdict(list)
    for entry in entries:
        clusters[entry["signature"]].append(entry)

    cluster_rows = []
    cluster_json = []
    for idx, (sig, members) in enumerate(
        sorted(clusters.items(), key=lambda kv: len(kv[1]), reverse=True), start=1
    ):
        cluster_id = f"C{idx:04d}"
        signals = sorted(set(m["signal"] for m in members))
        apps = sorted(set(m["app"] for m in members))
        harnesses = sorted(set(m["harness"] for m in members))
        samples = [m["stderr_path"] for m in members[: args.sample_per_cluster]]
        row = {
            "cluster_id": cluster_id,
            "count": len(members),
            "signals": "|".join(signals),
            "apps": "|".join(apps[:5]),
            "harnesses": "|".join(harnesses[:5]),
            "signature": sig[:400],
            "sample_stderr": samples[0] if samples else "",
        }
        cluster_rows.append(row)
        cluster_json.append(
            {
                "cluster_id": cluster_id,
                "count": len(members),
                "signals": signals,
                "apps": apps,
                "harnesses": harnesses,
                "signature": sig,
                "sample_stderr_paths": samples,
            }
        )

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    csv_path = out_dir / f"{args.out_prefix}_{run_id}.csv"
    json_path = out_dir / f"{args.out_prefix}_{run_id}.json"

    write_csv(cluster_rows, csv_path)
    json_path.write_text(
        json.dumps(
            {
                "total_crashes": len(entries),
                "unique_clusters": len(clusters),
                "input_dirs": args.input_dir,
                "clusters": cluster_json,
            },
            indent=2,
        )
    )

    print(f"[TRIAGE] total_crashes={len(entries)} unique_clusters={len(clusters)}")
    print(f"[TRIAGE] wrote CSV: {csv_path}")
    print(f"[TRIAGE] wrote JSON: {json_path}")


if __name__ == "__main__":
    main()
