import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_APK = REPO_ROOT / "target_APK"


def discover_constraint_files(app=None, harness=None):
    if app and harness:
        candidate = TARGET_APK / app / "harnesses" / harness / "seed_constraints.json"
        return [candidate] if candidate.exists() else []
    if app:
        return sorted((TARGET_APK / app).glob("harnesses/*/seed_constraints.json"))
    return sorted(TARGET_APK.glob("*/harnesses/*/seed_constraints.json"))


def parse_entry(path):
    app_name = path.parts[-4]
    harness_name = path.parts[-2]
    data = json.loads(path.read_text())
    entries = data.get("entries", [])

    jni_counter = Counter()
    constraint_counter = Counter()
    lv_count = 0

    for entry in entries:
        jni_type = entry.get("jni_type", "unknown")
        jni_counter[jni_type] += 1
        kind = entry.get("constraint_kind") or "none"
        constraint_counter[kind] += 1
        if entry.get("uses_lv_encoding"):
            lv_count += 1

    return {
        "app": app_name,
        "harness": harness_name,
        "nr_entries": len(entries),
        "lv_entries": lv_count,
        "jni_type_counts": dict(jni_counter),
        "constraint_kind_counts": dict(constraint_counter),
        "nr_seeds": data.get("nr_seeds"),
        "lv_size_bytes": data.get("lv_size_bytes"),
        "generic_size_bytes": data.get("generic_size_bytes"),
        "path": str(path),
    }


def print_table(rows):
    if not rows:
        print("No seed_constraints.json files found.")
        return

    header = f"{'APP':30} {'HARNESS':45} {'ARGS':>5} {'LV':>4} {'CONSTRAINTS':35}"
    print(header)
    print("-" * len(header))
    for row in rows:
        kinds = row["constraint_kind_counts"]
        kinds_str = ", ".join([f"{k}:{v}" for k, v in sorted(kinds.items())]) if kinds else "none"
        print(
            f"{row['app'][:30]:30} {row['harness'][:45]:45} {row['nr_entries']:>5} "
            f"{row['lv_entries']:>4} {kinds_str[:35]:35}"
        )


def print_aggregate(rows):
    if not rows:
        return
    total_harnesses = len(rows)
    total_args = sum(r["nr_entries"] for r in rows)
    total_lv = sum(r["lv_entries"] for r in rows)

    agg_jni = Counter()
    agg_kind = Counter()
    for row in rows:
        agg_jni.update(row["jni_type_counts"])
        agg_kind.update(row["constraint_kind_counts"])

    print("\nAggregate")
    print("---------")
    print(f"harnesses: {total_harnesses}")
    print(f"total_fuzz_args: {total_args}")
    print(f"total_lv_args: {total_lv}")
    print(f"jni_type_counts: {dict(agg_jni)}")
    print(f"constraint_kind_counts: {dict(agg_kind)}")


def print_top_constraints(rows, top_n):
    if not rows:
        return
    constraint_to_harnesses = defaultdict(int)
    for row in rows:
        for kind, count in row["constraint_kind_counts"].items():
            if kind == "none":
                continue
            constraint_to_harnesses[kind] += count
    if not constraint_to_harnesses:
        return
    print(f"\nTop {top_n} constraint kinds")
    print("---------------------------")
    for kind, count in sorted(constraint_to_harnesses.items(), key=lambda kv: kv[1], reverse=True)[:top_n]:
        print(f"{kind}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Summarize harness seed_constraints.json artifacts")
    parser.add_argument("--app", help="Filter by app name under target_APK")
    parser.add_argument("--harness", help="Filter by harness name (requires --app)")
    parser.add_argument("--json-out", help="Optional path to write JSON summary")
    parser.add_argument("--top", type=int, default=5, help="Show top-N constraint kinds (default: 5)")
    args = parser.parse_args()

    if args.harness and not args.app:
        raise SystemExit("--harness requires --app")

    files = discover_constraint_files(app=args.app, harness=args.harness)
    rows = [parse_entry(path) for path in files]

    print_table(rows)
    print_aggregate(rows)
    print_top_constraints(rows, top_n=args.top)

    if args.json_out:
        output = {
            "filters": {"app": args.app, "harness": args.harness},
            "count": len(rows),
            "rows": rows,
        }
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(output, indent=2))
        print(f"\nWrote JSON summary: {out_path}")


if __name__ == "__main__":
    main()
