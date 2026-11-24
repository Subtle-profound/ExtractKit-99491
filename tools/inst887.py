import pathlib
import subprocess
import time

ROOT = pathlib.Path(r"C:\Users\Admin\Documents\deepseek-harness\default-workspace")
ADB = str(ROOT / "android-sdk/platform-tools/adb.exe")
APK = str(ROOT / "ExtractKit-8.87-full.apk")


def run(args, timeout=180):
    return subprocess.run([ADB] + args, capture_output=True, timeout=timeout)


d = run(["devices"])
state = ""
lines = d.stdout.decode("utf-8", "replace").splitlines()
if len(lines) > 1:
    parts = lines[1].split()
    if len(parts) > 1:
        state = parts[1]
print("[adb]", state or "offline")
if state != "device":
    raise SystemExit(0)

print("[install]", run(["install", "-r", APK], 300).stdout.decode("utf-8", "replace").strip().splitlines()[-1:])
run(["shell", "am", "force-stop", "com.extractkit.app"])
run(["shell", "am", "start", "-n", "com.extractkit.app/.GlassMainActivity"])
time.sleep(6)
shot = run(["exec-out", "screencap", "-p"], 120)
(ROOT / "p887.png").write_bytes(shot.stdout)
print("[shot]", (ROOT / "p887.png").stat().st_size)
