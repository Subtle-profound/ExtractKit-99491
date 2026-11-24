"""8.84：用「已跑通设备」的旧 base 路径（BASE_LEGACY=1）出包，做 A/B 对照。"""
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
VER, CODE = "8.84", 184

env = dict(os.environ)
env["NDK"] = r"C:/AndroidSdk/android-ndk-r29"
env["JAVA_HOME"] = r"C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot"
env["EXTRA_CFLAGS"] = "-DBASE_LEGACY=1"

bp = subprocess.run(["python", str(ROOT / "tools/build_payload.py")], cwd=str(ROOT),
                    env=env, capture_output=True, text=True)
print("[payload]", bp.returncode)
tail = [l for l in (bp.stdout + bp.stderr).splitlines() if l.strip()][-6:]
print("\n".join(tail))
if bp.returncode != 0:
    sys.exit(1)

g = ROOT / "app/build.gradle.kts"
s = g.read_text(encoding="utf-8")
s = re.sub(r"versionCode\s*=\s*\d+", f"versionCode = {CODE}", s)
s = re.sub(r'versionName\s*=\s*"[^"]*"', f'versionName = "{VER}"', s)
g.write_text(s, encoding="utf-8", newline="\n")
print("[bump]", VER, CODE)

log = ROOT / "v884.log"
with log.open("w", encoding="utf-8", errors="replace") as fh:
    p = subprocess.run([str(ROOT / "gradlew.bat"), ":app:testDebugUnitTest",
                        ":app:assembleRelease", "--console=plain", "--no-daemon"],
                       cwd=str(ROOT), env=env, stdout=fh, stderr=subprocess.STDOUT, text=True)
print("[gradle] rc =", p.returncode)
print("\n".join(log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-5:]))
if p.returncode != 0:
    sys.exit(1)

apk = ROOT / "app/build/outputs/apk/release/app-release.apk"
out = ROOT.parent / f"ExtractKit-{VER}-legacybase.apk"
shutil.copyfile(apk, out)
d = out.read_bytes()
print(f"[apk] {out.name} {len(d)} B sha256={hashlib.sha256(d).hexdigest()}")
