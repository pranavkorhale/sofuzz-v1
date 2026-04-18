import argparse
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path


BASE_PATH = Path(__file__).resolve().parent
REPO_ROOT = BASE_PATH.parent
TARGET_APK_PATH = REPO_ROOT / "target_APK"
HARNESS_CPP_DIR = REPO_ROOT / "harness" / "cpp"
MAX_MUTATED_INPUT_SIZE = 65536
TYPE_SIZES = {
    "jbyte": 1,
    "jchar": 2,
    "jshort": 2,
    "jboolean": 1,
    "jint": 4,
    "jfloat": 4,
    "jdouble": 8,
    "jlong": 8,
}


def find_java_home():
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        return Path(java_home)

    javac = shutil.which("javac")
    if not javac:
        return None
    javac_path = Path(javac).resolve()
    # .../bin/javac
    if javac_path.parent.name == "bin":
        return javac_path.parent.parent
    return None


def get_jni_include_flags():
    java_home = find_java_home()
    if java_home is None:
        raise RuntimeError("JAVA_HOME is not set and javac was not found in PATH")

    include_dir = java_home / "include"
    if sys.platform == "darwin":
        platform_include = include_dir / "darwin"
    elif sys.platform.startswith("linux"):
        platform_include = include_dir / "linux"
    else:
        platform_include = include_dir / "win32"

    if not include_dir.exists() or not platform_include.exists():
        raise RuntimeError(
            f"JNI headers not found under JAVA_HOME ({java_home}). "
            "Expected include and platform-specific include folders."
        )

    return [f"-I{include_dir}", f"-I{platform_include}"]


def run_cmd(cmd, cwd=None, env=None):
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def compile_harness(harness_dir: Path):
    libharness_so = harness_dir / "libharness.so"
    harness_src = harness_dir / "harness_debug.cpp"
    harness_bin = harness_dir / "harness_debug"

    if not harness_src.exists():
        raise RuntimeError(f"missing harness source: {harness_src}")

    jni_flags = get_jni_include_flags()

    lib_cmd = [
        "g++",
        "-std=c++17",
        "-fPIC",
        "-Wall",
        "-shared",
        *jni_flags,
        str(HARNESS_CPP_DIR / "FuzzedDataProvider.cpp"),
        str(HARNESS_CPP_DIR / "libharness.cpp"),
        "-o",
        str(libharness_so),
    ]
    rc, out, err = run_cmd(lib_cmd, cwd=harness_dir)
    if rc != 0:
        raise RuntimeError(f"failed to compile libharness.so\nstdout:\n{out}\nstderr:\n{err}")

    harness_cmd = [
        "g++",
        "-std=c++17",
        "-Wall",
        "-Wl,--export-dynamic",
        "-Wl,-rpath,$ORIGIN",
        *jni_flags,
        str(harness_src),
        "-L.",
        "-lharness",
        "-o",
        str(harness_bin),
    ]
    rc, out, err = run_cmd(harness_cmd, cwd=harness_dir)
    if rc != 0:
        raise RuntimeError(f"failed to compile harness_debug\nstdout:\n{out}\nstderr:\n{err}")

    return harness_bin


def load_harness_info(harness_dir: Path):
    info_path = harness_dir / "info.json"
    if not info_path.exists():
        raise RuntimeError(f"missing harness metadata file: {info_path}")
    return json.loads(info_path.read_text())


def load_seed_constraints(harness_dir: Path):
    constraints_path = harness_dir / "seed_constraints.json"
    if not constraints_path.exists():
        return None
    try:
        return json.loads(constraints_path.read_text())
    except Exception:
        return None


def mutate_input(data: bytes, max_size: int = MAX_MUTATED_INPUT_SIZE):
    if len(data) == 0:
        data = b"\x00"

    buf = bytearray(data)
    ops = random.randint(1, 8)
    for _ in range(ops):
        op = random.choice(["flip", "set", "insert", "delete"])
        if op == "flip" and len(buf) > 0:
            idx = random.randrange(len(buf))
            bit = 1 << random.randrange(8)
            buf[idx] ^= bit
        elif op == "set" and len(buf) > 0:
            idx = random.randrange(len(buf))
            buf[idx] = random.randrange(256)
        elif op == "insert" and len(buf) < max_size:
            idx = random.randrange(len(buf) + 1)
            ins_len = random.randint(1, 16)
            chunk = bytes(random.randrange(256) for _ in range(ins_len))
            buf[idx:idx] = chunk
        elif op == "delete" and len(buf) > 1:
            idx = random.randrange(len(buf))
            del_len = random.randint(1, min(8, len(buf) - idx))
            del buf[idx : idx + del_len]
    return bytes(buf[:max_size])


def mutate_payload(payload: bytes, max_payload_size: int):
    buf = bytearray(payload if len(payload) > 0 else b"\x00")
    ops = random.randint(1, 4)
    for _ in range(ops):
        op = random.choice(["flip", "set", "insert", "delete"])
        if op == "flip" and len(buf) > 0:
            idx = random.randrange(len(buf))
            bit = 1 << random.randrange(8)
            buf[idx] ^= bit
        elif op == "set" and len(buf) > 0:
            idx = random.randrange(len(buf))
            buf[idx] = random.randrange(256)
        elif op == "insert" and len(buf) < max_payload_size:
            idx = random.randrange(len(buf) + 1)
            ins_len = random.randint(1, min(8, max_payload_size - len(buf)))
            if ins_len > 0:
                chunk = bytes(random.randrange(256) for _ in range(ins_len))
                buf[idx:idx] = chunk
        elif op == "delete" and len(buf) > 1:
            idx = random.randrange(len(buf))
            del_len = random.randint(1, min(8, len(buf) - idx))
            del buf[idx : idx + del_len]
    return bytes(buf[:max_payload_size])


def parse_seed_fields(data: bytes, seed_constraints):
    entries = seed_constraints.get("entries", [])
    lv_size = int(seed_constraints.get("lv_size_bytes", 3))
    if len(entries) == 0:
        return None

    fields = []
    cursor = 0
    for i, entry in enumerate(entries):
        jni_type = entry.get("jni_type")
        uses_lv = bool(entry.get("uses_lv_encoding"))
        fixed_size = TYPE_SIZES.get(jni_type)
        is_last = i == (len(entries) - 1)

        if fixed_size is not None:
            if cursor + fixed_size > len(data):
                return None
            raw = data[cursor : cursor + fixed_size]
            fields.append(
                {
                    "kind": "fixed",
                    "jni_type": jni_type,
                    "uses_lv_encoding": False,
                    "raw": raw,
                }
            )
            cursor += fixed_size
            continue

        if uses_lv:
            if cursor + lv_size > len(data):
                return None
            len_prefix = data[cursor : cursor + lv_size]
            payload_len = int.from_bytes(len_prefix, "little", signed=False)
            cursor += lv_size
            available = len(data) - cursor
            payload_len = min(payload_len, max(available, 0))
            payload = data[cursor : cursor + payload_len]
            cursor += payload_len
            fields.append(
                {
                    "kind": "variable",
                    "jni_type": jni_type,
                    "uses_lv_encoding": True,
                    "len_prefix": len_prefix,
                    "payload": payload,
                }
            )
        else:
            # Last variable-length field consumes the remaining bytes.
            payload = data[cursor:] if is_last else b""
            cursor = len(data) if is_last else cursor
            fields.append(
                {
                    "kind": "variable",
                    "jni_type": jni_type,
                    "uses_lv_encoding": False,
                    "payload": payload,
                }
            )
    return fields


def rebuild_seed_from_fields(fields, lv_size, max_size):
    out = bytearray()
    for field in fields:
        if field["kind"] == "fixed":
            out += field["raw"]
            continue
        payload = field.get("payload", b"")
        if field.get("uses_lv_encoding", False):
            out += len(payload).to_bytes(lv_size, "little", signed=False)
        out += payload
        if len(out) >= max_size:
            return bytes(out[:max_size])
    return bytes(out)


def mutate_structured_input(data: bytes, seed_constraints, max_size: int = MAX_MUTATED_INPUT_SIZE):
    fields = parse_seed_fields(data, seed_constraints)
    if not fields:
        return mutate_input(data, max_size=max_size), False, False

    idx = random.randrange(len(fields))
    field = fields[idx]
    if field["kind"] == "fixed":
        raw = bytearray(field["raw"])
        if len(raw) == 0:
            raw = bytearray(b"\x00")
        op = random.choice(["flip", "set"])
        pos = random.randrange(len(raw))
        if op == "flip":
            raw[pos] ^= 1 << random.randrange(8)
        else:
            raw[pos] = random.randrange(256)
        field["raw"] = bytes(raw)
    else:
        current_total = len(data)
        current_payload_len = len(field.get("payload", b""))
        max_payload_size = max(1, current_payload_len + max(0, max_size - current_total))
        field["payload"] = mutate_payload(field.get("payload", b""), max_payload_size=max_payload_size)

    lv_size = int(seed_constraints.get("lv_size_bytes", 3))
    mutated = rebuild_seed_from_fields(fields, lv_size=lv_size, max_size=max_size)
    if len(mutated) == 0:
        mutated = b"\x00"
    return mutated, True, True


def classify_crash(returncode: int, stdout: str, stderr: str):
    combined = f"{stdout}\n{stderr}"
    if returncode < 0:
        try:
            return f"signal_{signal.Signals(-returncode).name}"
        except Exception:
            return f"signal_{-returncode}"
    if returncode > 0:
        return f"exit_{returncode}"
    if "EXITED DUE TO SIGNAL" in combined:
        return "signal_reported"
    return None


def fuzz_host(app: str, harness_name: str, duration: int, timeout: int, rebuild: bool):
    app_dir = TARGET_APK_PATH / app
    harness_dir = app_dir / "harnesses" / harness_name
    if not harness_dir.exists():
        raise RuntimeError(f"harness does not exist: {harness_dir}")

    info = load_harness_info(harness_dir)
    target_library = info.get("targetlibrary")
    target_class = info.get("targetclassname")
    if not target_library or not target_class:
        raise RuntimeError("info.json is missing targetlibrary or targetclassname")

    harness_bin = harness_dir / "harness_debug"
    if rebuild or not harness_bin.exists():
        print(f"[HOST-FUZZ] compiling harness in {harness_dir}")
        harness_bin = compile_harness(harness_dir)

    seed_constraints = load_seed_constraints(harness_dir)

    seeds_dir = harness_dir / "seeds"
    seed_files = sorted(list(seeds_dir.glob("*"))) if seeds_dir.exists() else []
    if not seed_files:
        # fallback seed so runner can start even if seed generation was skipped
        seed_data = [b"\x00"]
    else:
        seed_data = [p.read_bytes() for p in seed_files if p.is_file()]
        if len(seed_data) == 0:
            seed_data = [b"\x00"]

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_dir = app_dir / "fuzzing_output_host" / harness_name / f"output_host_{timestamp}"
    crashes_dir = out_dir / "crashes"
    queue_dir = out_dir / "queue"
    logs_dir = out_dir / "logs"
    crashes_dir.mkdir(parents=True, exist_ok=True)
    queue_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["ANDROLIB_MEMORY"] = str(out_dir / "memory")
    env["ANDROLIB_APP_PATH"] = str(app_dir)
    env["ANDROLIB_TARGET_LIBRARY"] = target_library
    env["ANDROLIB_CLASS0"] = target_class

    lib_path = str(app_dir / "lib" / "arm64-v8a")
    harness_lib_path = str(harness_dir)
    if "LD_LIBRARY_PATH" in env and env["LD_LIBRARY_PATH"]:
        env["LD_LIBRARY_PATH"] = f"{harness_lib_path}:{lib_path}:{env['LD_LIBRARY_PATH']}"
    else:
        env["LD_LIBRARY_PATH"] = f"{harness_lib_path}:{lib_path}"

    start = time.time()
    total = 0
    crashes = 0
    structured_mutations = 0
    parse_attempts = 0
    parse_successes = 0
    compile_or_runtime_hint_written = False

    with tempfile.TemporaryDirectory(prefix="host_fuzz_") as tmp_dir:
        tmp_input = Path(tmp_dir) / "input.bin"

        while time.time() - start < duration:
            base = random.choice(seed_data)
            if seed_constraints is not None:
                parse_attempts += 1
                mutated, used_structured, parsed_ok = mutate_structured_input(
                    base, seed_constraints, max_size=MAX_MUTATED_INPUT_SIZE
                )
                if parsed_ok:
                    parse_successes += 1
                if used_structured:
                    structured_mutations += 1
            else:
                mutated = mutate_input(base, max_size=MAX_MUTATED_INPUT_SIZE)
            tmp_input.write_bytes(mutated)

            # do_memdump=0, do_fork=0 for easier crash signal handling
            cmd = [str(harness_bin), str(tmp_input), "0", "0"]
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=harness_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                total += 1
                continue
            total += 1

            crash_reason = classify_crash(proc.returncode, proc.stdout, proc.stderr)
            if crash_reason:
                crash_name = f"id_{crashes:06d}_{crash_reason}.bin"
                (crashes_dir / crash_name).write_bytes(mutated)
                (logs_dir / f"{crash_name}.stdout.txt").write_text(proc.stdout)
                (logs_dir / f"{crash_name}.stderr.txt").write_text(proc.stderr)
                crashes += 1
            elif total % 25 == 0:
                queue_name = f"id_{total:06d}.bin"
                (queue_dir / queue_name).write_bytes(mutated)

            # common first-run failure signal in host mode if Android libs are missing
            if (
                total < 5
                and not compile_or_runtime_hint_written
                and ("libart.so" in proc.stderr or "libandroid_runtime.so" in proc.stderr)
            ):
                hint = (
                    "Runtime dependency missing: host execution needs Android runtime libs "
                    "(libart.so, libandroid_runtime.so) available in loader path."
                )
                (out_dir / "HOST_RUNTIME_HINT.txt").write_text(hint)
                compile_or_runtime_hint_written = True

    summary = {
        "app": app,
        "harness": harness_name,
        "duration_seconds": duration,
        "timeout_seconds": timeout,
        "executions": total,
        "crashes": crashes,
        "output_dir": str(out_dir),
        "target_library": target_library,
        "target_class": target_class,
        "mutation_mode": "structured" if seed_constraints is not None else "byte",
        "structured_mutations": structured_mutations,
        "seed_parse_attempts": parse_attempts,
        "seed_parse_successes": parse_successes,
        "seed_parse_success_rate": (parse_successes / parse_attempts) if parse_attempts > 0 else None,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


def main():
    parser = argparse.ArgumentParser(description="Host-only native fuzzing without device/emulator")
    parser.add_argument("--target", required=True, help="app folder name under target_APK")
    parser.add_argument("--target_function", required=True, help="harness folder name under target_APK/<app>/harnesses")
    parser.add_argument("-t", "--time", type=int, default=300, help="fuzz time in seconds")
    parser.add_argument("--timeout", type=int, default=3, help="per-execution timeout in seconds")
    parser.add_argument("--rebuild", action="store_true", help="force rebuild harness binary")
    args = parser.parse_args()

    random.seed()
    summary = fuzz_host(
        app=args.target,
        harness_name=args.target_function,
        duration=args.time,
        timeout=args.timeout,
        rebuild=args.rebuild,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
