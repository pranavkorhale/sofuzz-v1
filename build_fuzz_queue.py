import json
import os
import sqlite3
import subprocess

import fuzzing.lib.apk_db as apk_db


BASE = os.path.dirname(__file__)
TARGET_APK_PATH = os.path.join(BASE, "./target_APK")

if "HARNESS_GEN_FLAGS" in os.environ:
    HARNESS_GEN_FLAGS = os.environ["HARNESS_GEN_FLAGS"]
else:
    HARNESS_GEN_FLAGS = "-jo_ok -cs_ph -cs_io -cs_ph_min_len 0 -ct_argval -fuzz"

os.system(f"rm -f {BASE}/harness/cpp/libharness.so")
os.system(f"rm -f {BASE}/harness/cpp/libharness_debug.so")
if os.path.exists(f"{BASE}/fuzzing/fuzz.db"):
    os.makedirs(f"{BASE}/db_backups", exist_ok=True)
    os.system(f"mv {BASE}/fuzzing/fuzz.db {BASE}/db_backups/fuzz_backupped.db")
os.system(f"rm -f {BASE}/fuzz.db")
apk_db.init_db()
con = apk_db.open_db()

FNAME_WHITELIST = None
UNIQUE_FNAMES = False


def is_already_fuzzed(harness_name):
    cur = con.cursor()
    update_query = "SELECT * FROM fuzzdata WHERE fname == ?"
    cur.execute(update_query, (harness_name,))
    rows = cur.fetchall()
    cur.close()
    return len(rows) > 0


def add_apk(apk_name, fname_allowlist=None):
    print(f"adding apk: {apk_name}")
    cur = con.cursor()
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk_name, "base.apk")):
        print("NO APK for app ignoring!")
        print(os.path.join(TARGET_APK_PATH, apk_name, "base.apk"))
        cur.close()
        return
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk_name, "signatures_pattern.txt")):
        print(f"extracting native sigs {apk_name} (signature extraction)")
        subprocess.check_output(
            f"python3 static_analysis/preprocess.py --target {apk_name} --signatures --static_only",
            shell=True,
        )
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk_name, "signatures_libraries_offsets.txt")):
        print("STATIC-ONLY: signatures_libraries_offsets.txt not present, using signatures_pattern.txt fallback")

    harnesses = os.path.join(TARGET_APK_PATH, apk_name, "harnesses")

    if (
        not os.path.exists(os.path.join(TARGET_APK_PATH, apk_name, "static_analysis", f"CS_{apk_name}.json"))
        or len(open(os.path.join(TARGET_APK_PATH, apk_name, "static_analysis", f"CS_{apk_name}.json"), "r").read()) < 4
    ):
        print("FIXME PHENOMENON NOT PRESENT")

    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk_name, "static_analysis", "simple_argument_constraints.txt")):
        print("FIXME simple_argument_constraints.txt NOT PRESENT")

    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk_name, "harnesses", "meta_harness2nrfuzzargs.json")):
        print("FIXME meta_harness2nrfuzzargs.json NOT PRESENT")

    print(f"Ready {apk_name}")
    harnesses = os.listdir(harnesses)
    if "APP2FNAME" in os.environ:
        app2fname = json.load(open(os.environ["APP2FNAME"]))
    else:
        app2fname = None

    for harness_name in harnesses:
        if harness_name.endswith(".json"):
            continue
        if not os.path.exists(os.path.join(TARGET_APK_PATH, apk_name, "harnesses", harness_name)):
            continue
        if "Java_hl_productor_fxlib_HLRenderThread" in harness_name:
            continue

        if app2fname is not None:
            if apk_name not in app2fname:
                continue
            if harness_name.split("@")[0] not in app2fname[apk_name]:
                continue
        try:
            if UNIQUE_FNAMES and is_already_fuzzed(harness_name):
                print(f"Harness already in db, skipping: {harness_name}")
                continue
            update_query = "INSERT INTO fuzzdata (app, fname) VALUES (?, ?)"
            cur.execute(update_query, (apk_name, harness_name))
            con.commit()
        except sqlite3.IntegrityError:
            print("integrity error")
            continue

    cur.close()


if __name__ == "__main__":
    if "APKS" not in os.environ:
        print("specify APKS")
        raise SystemExit(1)

    apks = open(os.environ["APKS"]).read().split("\n")
    for apk_name in apks:
        if apk_name == "":
            continue
        add_apk(apk_name)
    subprocess.check_output(f"cp {BASE}/fuzz.db {BASE}/fuzzing/fuzz.db", shell=True)
