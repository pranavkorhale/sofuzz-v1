import os
import subprocess
import sys

BASE = os.path.dirname(__file__)
TARGET_APK_PATH = os.path.join(BASE, "./target_APK")


def run_static_preprocess(apk_name):
    print(f"[STATIC] processing {apk_name}")
    clean = "CLEAN" in os.environ
    if not os.path.exists(os.path.join(TARGET_APK_PATH, apk_name, "base.apk")):
        print(f"[STATIC] NO APK for app {apk_name}, ignoring")
        return
    if clean:
        for file_path in [
            os.path.join(TARGET_APK_PATH, apk_name, "signatures_pattern.txt"),
            os.path.join(TARGET_APK_PATH, apk_name, "signatures_libraries_offsets.txt"),
            os.path.join(TARGET_APK_PATH, apk_name, "static_analysis", "simple_argument_constraints.txt"),
            os.path.join(TARGET_APK_PATH, apk_name, "static_analysis", f"CS_{apk_name}.json"),
        ]:
            if os.path.exists(file_path):
                os.remove(file_path)

    signatures_path = os.path.join(TARGET_APK_PATH, apk_name, "signatures_pattern.txt")
    argument_constraints_path = os.path.join(TARGET_APK_PATH, apk_name, "static_analysis", "simple_argument_constraints.txt")
    callsequence_path = os.path.join(TARGET_APK_PATH, apk_name, "static_analysis", f"CS_{apk_name}.json")

    if not os.path.exists(signatures_path):
        print(f"[STATIC] extracting native signatures for {apk_name}")
        subprocess.check_call(
            ["python3", "static_analysis/preprocess.py", "--target", apk_name, "--signatures", "--static_only"]
        )

    if not os.path.exists(argument_constraints_path):
        print(f"[STATIC] running argument analysis for {apk_name}")
        subprocess.check_call(
            ["python3", "static_analysis/preprocess.py", "--target", apk_name, "--argument_analysis", "--static_only"]
        )

    if not os.path.exists(callsequence_path):
        print(f"[STATIC] running callsequence analysis for {apk_name}")
        subprocess.check_call(
            ["python3", "static_analysis/preprocess.py", "--target", apk_name, "--callsequence_analysis", "--static_only"]
        )


if __name__ == "__main__":
    if "APKS" not in os.environ:
        print("specify APKS env variable and point to file with apks")
        sys.exit(1)

    apk_list = open(os.environ["APKS"]).read().split("\n")
    for apk_name in apk_list:
        if apk_name == "":
            continue
        run_static_preprocess(apk_name)
