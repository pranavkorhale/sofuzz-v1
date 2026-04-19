import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET_APK = REPO_ROOT / "target_APK"
DEFAULT_OUTPUT = REPO_ROOT / "results" / "seed_pool.json"


def build_signature_key(info_data, constraints_data):
    callsequence = info_data.get("callsequence")
    if isinstance(callsequence, list) and callsequence:
        target = callsequence[-1]
        signature = target.get("signature", {})
        ret_type = signature.get("ret_type", "unknown")
        args = signature.get("args", [])
        arg_types = [arg.get("type", "unknown") for arg in args]
        return f"{ret_type}|{','.join(arg_types)}", "info_json_callsequence"

    entries = constraints_data.get("entries", [])
    jni_types = [entry.get("jni_type", "unknown") for entry in entries]
    # Fallback key when info.json/callsequence is missing.
    return f"seedplan|{','.join(jni_types)}", "seed_constraints_entries"


def discover_harnesses(target_apk):
    return sorted(target_apk.glob("*/harnesses/*"))


def parse_harness(harness_path):
    app = harness_path.parts[-3]
    harness = harness_path.name
    seeds_dir = harness_path / "seeds"
    info_path = harness_path / "info.json"
    constraints_path = harness_path / "seed_constraints.json"

    if not seeds_dir.exists() or not constraints_path.exists():
        return None

    seed_files = sorted([p for p in seeds_dir.iterdir() if p.is_file()])
    if not seed_files:
        return None

    info_data = {}
    if info_path.exists():
        try:
            info_data = json.loads(info_path.read_text())
        except json.JSONDecodeError:
            info_data = {}

    try:
        constraints_data = json.loads(constraints_path.read_text())
    except json.JSONDecodeError:
        return None

    key, key_source = build_signature_key(info_data, constraints_data)
    return {
        "app": app,
        "harness": harness,
        "signature_key": key,
        "key_source": key_source,
        "seed_count": len(seed_files),
        "seed_files": [str(p.relative_to(REPO_ROOT)) for p in seed_files],
        "harness_path": str(harness_path.relative_to(REPO_ROOT)),
        "constraints_path": str(constraints_path.relative_to(REPO_ROOT)),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Build a cross-app seed pool grouped by JNI signature key."
    )
    parser.add_argument(
        "--target-apk",
        default=str(DEFAULT_TARGET_APK),
        help="Path to target_APK root (default: repo/target_APK)",
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUTPUT),
        help="Output JSON path (default: results/seed_pool.json)",
    )
    parser.add_argument(
        "--min-seeds",
        type=int,
        default=1,
        help="Minimum number of local seeds required to include harness (default: 1)",
    )
    args = parser.parse_args()

    target_apk = Path(args.target_apk).resolve()
    out_path = Path(args.out).resolve()

    rows = []
    for harness_path in discover_harnesses(target_apk):
        row = parse_harness(harness_path)
        if row is None:
            continue
        if row["seed_count"] < args.min_seeds:
            continue
        rows.append(row)

    by_key = {}
    for row in rows:
        key = row["signature_key"]
        by_key.setdefault(key, [])
        by_key[key].append(
            {
                "app": row["app"],
                "harness": row["harness"],
                "seed_count": row["seed_count"],
                "seed_files": row["seed_files"],
                "harness_path": row["harness_path"],
                "key_source": row["key_source"],
            }
        )

    output = {
        "count_harnesses": len(rows),
        "count_keys": len(by_key),
        "entries": rows,
        "pool": by_key,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2))
    print(f"[SEED-POOL] wrote: {out_path}")
    print(f"[SEED-POOL] harnesses: {len(rows)} keys: {len(by_key)}")


if __name__ == "__main__":
    main()
