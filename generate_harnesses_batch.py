import os
import subprocess


if "HARNESS_GEN_FLAGS" not in os.environ:
    print("HARNESS_GEN_FLAGS not set")
    raise SystemExit(-1)

if "APKS" not in os.environ:
    print("specify APKS")
    raise SystemExit(-11)

HARNESS_GEN_FLAGS = os.environ["HARNESS_GEN_FLAGS"]
apks = open(os.environ["APKS"]).read().split("\n")
TARGET_APK_PATH = os.path.join(os.path.dirname(__file__), "target_APK")

for apk_name in apks:
    if apk_name == "":
        continue
    base_apk = os.path.join(TARGET_APK_PATH, apk_name, "base.apk")
    if not os.path.exists(base_apk):
        print(f"[HARNESS-BATCH] skipping {apk_name}: missing {base_apk}")
        continue
    subprocess.check_output(
        f"python3 harness/harness_generator.py {HARNESS_GEN_FLAGS} --target {apk_name}",
        shell=True,
    )
