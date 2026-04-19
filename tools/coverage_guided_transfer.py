"""
Coverage-guided cross-app seed transfer.

Filters signature-compatible candidate seeds by probing them once on the target
harness and keeping only those that produce a *new* observable behavior
fingerprint compared to:
  - probes of local seeds in the target harness
  - already-accepted transferred seeds

This upgrades naive (signature-only) transfer to utility-aware transfer.

Output:
  - target_APK/<app>/harnesses/<harness>/seeds_transfer/<src_app>__<src_harness>__<file>
  - target_APK/<app>/harnesses/<harness>/seeds_transfer/_provenance.json
  - results/coverage_guided_transfer_<app>_<harness>_<run_id>.json
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_APK = REPO_ROOT / "target_APK"
DEFAULT_POOL = REPO_ROOT / "results" / "seed_pool.json"
DEFAULT_OUT_DIR = REPO_ROOT / "results"

sys.path.insert(0, str(REPO_ROOT))
from fuzzing.host_fuzz import (  # noqa: E402
    classify_crash,
    compile_harness,
    detect_runtime_dependency_error,
    load_harness_info,
)


HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
LONG_NUM_RE = re.compile(r"\b\d{5,}\b")


def normalize_line(line):
    out = line.strip()
    if not out:
        return out
    out = HEX_RE.sub("0xADDR", out)
    out = LONG_NUM_RE.sub("NUM", out)
    return out


def length_bucket(n):
    if n <= 0:
        return "0"
    if n < 64:
        return "xs"
    if n < 1024:
        return "s"
    if n < 16384:
        return "m"
    return "l"


def duration_bucket(seconds):
    if seconds < 0.1:
        return "<0.1s"
    if seconds < 0.5:
        return "<0.5s"
    if seconds < 1.0:
        return "<1s"
    if seconds < 3.0:
        return "<3s"
    return ">=3s"


def fingerprint(returncode, stdout, stderr, duration, max_lines=3):
    crash_kind = classify_crash(returncode, stdout, stderr) or "ok"
    head = []
    for line in stderr.splitlines():
        norm = normalize_line(line)
        if not norm:
            continue
        head.append(norm)
        if len(head) >= max_lines:
            break
    return "|".join(
        [
            crash_kind,
            length_bucket(len(stdout)),
            length_bucket(len(stderr)),
            duration_bucket(duration),
            " || ".join(head),
        ]
    )


def build_env(app_dir, harness_dir):
    env = os.environ.copy()
    env["ANDROLIB_APP_PATH"] = str(app_dir)
    lib_path = str(app_dir / "lib" / "arm64-v8a")
    harness_lib_path = str(harness_dir)
    if env.get("LD_LIBRARY_PATH"):
        env["LD_LIBRARY_PATH"] = f"{harness_lib_path}:{lib_path}:{env['LD_LIBRARY_PATH']}"
    else:
        env["LD_LIBRARY_PATH"] = f"{harness_lib_path}:{lib_path}"
    return env


def probe_seed(harness_bin, harness_dir, env, data, timeout):
    with tempfile.TemporaryDirectory(prefix="cg_transfer_") as tmp_dir:
        tmp_input = Path(tmp_dir) / "input.bin"
        tmp_input.write_bytes(data if data else b"\x00")
        cmd = [str(harness_bin), str(tmp_input), "0", "0"]
        start = datetime.now(timezone.utc)
        try:
            proc = subprocess.run(
                cmd,
                cwd=harness_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            duration = (datetime.now(timezone.utc) - start).total_seconds()
            return {
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "duration": duration,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as exc:
            duration = (datetime.now(timezone.utc) - start).total_seconds()
            return {
                "returncode": -1,
                "stdout": exc.stdout or "",
                "stderr": (exc.stderr or "") + "\n[TIMEOUT]",
                "duration": duration,
                "timed_out": True,
            }


def load_pool(pool_path):
    data = json.loads(pool_path.read_text())
    return data.get("entries", []), data.get("pool", {})


def locate_target_entry(entries, app, harness):
    for entry in entries:
        if entry.get("app") == app and entry.get("harness") == harness:
            return entry
    return None


def list_local_seeds(harness_dir):
    seeds_dir = harness_dir / "seeds"
    if not seeds_dir.exists():
        return []
    return sorted([p for p in seeds_dir.iterdir() if p.is_file()])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, help="Target app under target_APK")
    parser.add_argument("--harness", required=True, help="Target harness folder name")
    parser.add_argument(
        "--pool",
        default=str(DEFAULT_POOL),
        help="Path to seed_pool.json (default: results/seed_pool.json)",
    )
    parser.add_argument(
        "--max-keep",
        type=int,
        default=20,
        help="Maximum number of transferred seeds to accept (default: 20)",
    )
    parser.add_argument(
        "--probe-timeout",
        type=int,
        default=3,
        help="Per-probe timeout seconds (default: 3)",
    )
    parser.add_argument(
        "--allow-same-app",
        action="store_true",
        help="Allow transferring seeds from harnesses in the same app",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete existing seeds_transfer folder before populating",
    )
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Where to write run-level summary JSON (default: results/)",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip Android runtime dependency check (degraded probing).",
    )
    args = parser.parse_args()

    pool_path = Path(args.pool).resolve()
    if not pool_path.exists():
        raise SystemExit(f"seed pool not found: {pool_path}")

    app_dir = TARGET_APK / args.app
    harness_dir = app_dir / "harnesses" / args.harness
    if not harness_dir.exists():
        raise SystemExit(f"harness directory not found: {harness_dir}")

    info = load_harness_info(harness_dir)
    if not info.get("targetlibrary") or not info.get("targetclassname"):
        raise SystemExit("info.json missing targetlibrary or targetclassname")

    entries, pool = load_pool(pool_path)
    target_entry = locate_target_entry(entries, args.app, args.harness)
    if target_entry is None:
        raise SystemExit("target harness not present in seed pool; run build_seed_pool.py first")

    key = target_entry["signature_key"]
    candidates = pool.get(key, [])

    print(f"[CG-TRANSFER] app={args.app} harness={args.harness} key={key}")
    print(f"[CG-TRANSFER] candidate sources={len(candidates)}")

    print("[CG-TRANSFER] compiling target harness")
    harness_bin = compile_harness(harness_dir)
    env = build_env(app_dir=app_dir, harness_dir=harness_dir)

    local_seeds = list_local_seeds(harness_dir)
    seen = set()

    print(f"[CG-TRANSFER] probing {len(local_seeds)} local seed(s) for baseline behavior")
    baseline_fps = []
    for seed_path in local_seeds:
        result = probe_seed(
            harness_bin=harness_bin,
            harness_dir=harness_dir,
            env=env,
            data=seed_path.read_bytes(),
            timeout=args.probe_timeout,
        )
        missing = detect_runtime_dependency_error(result["stderr"])
        if missing and not args.skip_preflight:
            raise SystemExit(
                f"Host runtime dependency missing: {missing}. "
                "Provide Android runtime libs in LD_LIBRARY_PATH and retry, "
                "or pass --skip-preflight for degraded probing."
            )
        fp = fingerprint(
            returncode=result["returncode"],
            stdout=result["stdout"],
            stderr=result["stderr"],
            duration=result["duration"],
        )
        seen.add(fp)
        baseline_fps.append({"seed": seed_path.name, "fingerprint": fp})

    transfer_dir = harness_dir / "seeds_transfer"
    if args.clean and transfer_dir.exists():
        shutil.rmtree(transfer_dir)
    transfer_dir.mkdir(parents=True, exist_ok=True)

    accepted = 0
    rejected_dup = 0
    rejected_error = 0
    rejected_same_app = 0
    decisions = []

    for source in candidates:
        if accepted >= args.max_keep:
            break
        src_app = source.get("app")
        src_harness = source.get("harness")
        if src_app == args.app and src_harness == args.harness:
            continue
        if not args.allow_same_app and src_app == args.app:
            rejected_same_app += 1
            continue
        for seed_rel in source.get("seed_files", []):
            if accepted >= args.max_keep:
                break
            seed_path = REPO_ROOT / seed_rel
            if not seed_path.exists():
                rejected_error += 1
                decisions.append(
                    {
                        "src_app": src_app,
                        "src_harness": src_harness,
                        "seed": seed_rel,
                        "decision": "missing_file",
                    }
                )
                continue
            data = seed_path.read_bytes()
            result = probe_seed(
                harness_bin=harness_bin,
                harness_dir=harness_dir,
                env=env,
                data=data,
                timeout=args.probe_timeout,
            )
            fp = fingerprint(
                returncode=result["returncode"],
                stdout=result["stdout"],
                stderr=result["stderr"],
                duration=result["duration"],
            )
            if fp in seen:
                rejected_dup += 1
                decisions.append(
                    {
                        "src_app": src_app,
                        "src_harness": src_harness,
                        "seed": seed_rel,
                        "fingerprint": fp,
                        "decision": "reject_duplicate",
                    }
                )
                continue
            seen.add(fp)
            dst_name = f"{src_app}__{src_harness}__{seed_path.name}"
            shutil.copy2(seed_path, transfer_dir / dst_name)
            accepted += 1
            decisions.append(
                {
                    "src_app": src_app,
                    "src_harness": src_harness,
                    "seed": seed_rel,
                    "fingerprint": fp,
                    "decision": "accept",
                    "saved_as": dst_name,
                }
            )

    provenance = {
        "app": args.app,
        "harness": args.harness,
        "signature_key": key,
        "max_keep": args.max_keep,
        "probe_timeout": args.probe_timeout,
        "allow_same_app": args.allow_same_app,
        "baseline_local_fingerprints": baseline_fps,
        "accepted": accepted,
        "rejected_duplicate": rejected_dup,
        "rejected_error": rejected_error,
        "rejected_same_app": rejected_same_app,
        "unique_baseline_fps": len({fp["fingerprint"] for fp in baseline_fps}),
        "unique_total_fps": len(seen),
        "decisions": decisions,
    }
    (transfer_dir / "_provenance.json").write_text(json.dumps(provenance, indent=2))

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    summary_path = (
        out_dir / f"coverage_guided_transfer_{args.app}_{args.harness}_{run_id}.json"
    )
    summary_path.write_text(json.dumps(provenance, indent=2))

    print(
        "[CG-TRANSFER] "
        f"accepted={accepted} rejected_duplicate={rejected_dup} "
        f"rejected_error={rejected_error} rejected_same_app={rejected_same_app}"
    )
    print(f"[CG-TRANSFER] provenance: {transfer_dir / '_provenance.json'}")
    print(f"[CG-TRANSFER] summary: {summary_path}")


if __name__ == "__main__":
    main()
