import argparse
import json
import shutil
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET_APK = REPO_ROOT / "target_APK"
DEFAULT_POOL = REPO_ROOT / "results" / "seed_pool.json"


def load_pool(pool_path):
    data = json.loads(pool_path.read_text())
    return data.get("entries", []), data.get("pool", {})


def target_harness_paths(target_apk, app=None, harness=None):
    if app and harness:
        return [target_apk / app / "harnesses" / harness]
    if app:
        return sorted((target_apk / app / "harnesses").glob("*"))
    return sorted(target_apk.glob("*/harnesses/*"))


def locate_entry(entries, app, harness):
    for entry in entries:
        if entry.get("app") == app and entry.get("harness") == harness:
            return entry
    return None


def copy_transfer_seeds(
    target_entry,
    candidates,
    transfer_dir,
    max_transfer,
    allow_same_app=False,
):
    copied = 0
    seen = set()
    for source in candidates:
        if copied >= max_transfer:
            break
        source_app = source.get("app")
        source_harness = source.get("harness")
        if source_app == target_entry["app"] and source_harness == target_entry["harness"]:
            continue
        if not allow_same_app and source_app == target_entry["app"]:
            continue
        for seed_file in source.get("seed_files", []):
            if copied >= max_transfer:
                break
            src = REPO_ROOT / seed_file
            if not src.exists():
                continue
            # Prevent duplicate content by source path.
            if str(src) in seen:
                continue
            seen.add(str(src))
            dst = transfer_dir / f"{source_app}__{source_harness}__{src.name}"
            shutil.copy2(src, dst)
            copied += 1
    return copied


def main():
    parser = argparse.ArgumentParser(
        description="Apply cross-app seed transfer using seed_pool.json."
    )
    parser.add_argument(
        "--pool",
        default=str(DEFAULT_POOL),
        help="Path to seed_pool.json (default: results/seed_pool.json)",
    )
    parser.add_argument(
        "--target-apk",
        default=str(DEFAULT_TARGET_APK),
        help="Path to target_APK root (default: repo/target_APK)",
    )
    parser.add_argument("--app", help="Optional target app filter")
    parser.add_argument("--harness", help="Optional target harness filter (requires --app)")
    parser.add_argument(
        "--max-transfer",
        type=int,
        default=20,
        help="Max transferred seeds per harness (default: 20)",
    )
    parser.add_argument(
        "--allow-same-app",
        action="store_true",
        help="Allow transferring seeds from harnesses in same app",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete existing seeds_transfer folder before copying",
    )
    args = parser.parse_args()

    if args.harness and not args.app:
        raise SystemExit("--harness requires --app")

    pool_path = Path(args.pool).resolve()
    target_apk = Path(args.target_apk).resolve()
    entries, pool = load_pool(pool_path)

    targets = target_harness_paths(target_apk, app=args.app, harness=args.harness)
    total_targets = 0
    total_copied = 0

    for harness_path in targets:
        if not harness_path.exists():
            continue
        app_name = harness_path.parts[-3]
        harness_name = harness_path.name
        target_entry = locate_entry(entries, app_name, harness_name)
        if target_entry is None:
            continue
        key = target_entry["signature_key"]
        candidates = pool.get(key, [])
        transfer_dir = harness_path / "seeds_transfer"

        if args.clean and transfer_dir.exists():
            shutil.rmtree(transfer_dir)
        transfer_dir.mkdir(parents=True, exist_ok=True)

        copied = copy_transfer_seeds(
            target_entry=target_entry,
            candidates=candidates,
            transfer_dir=transfer_dir,
            max_transfer=args.max_transfer,
            allow_same_app=args.allow_same_app,
        )
        total_targets += 1
        total_copied += copied
        print(
            f"[SEED-TRANSFER] {app_name}/{harness_name} key={key} copied={copied}"
        )

    print(
        f"[SEED-TRANSFER] done targets={total_targets} total_copied={total_copied}"
    )


if __name__ == "__main__":
    main()
