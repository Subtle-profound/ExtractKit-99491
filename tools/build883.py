"""8.83：放宽 base 下界（负 slide）+ 打印样本 site/slide，重编 payload 并出包。"""
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
VER, CODE = "8.83", 183

# 1) payload
NDK = r"C:/AndroidSdk/android-ndk-r29"
env = dict(os.environ)
env["NDK"] = NDK
env["JAVA_HOME"] = r"C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot"

bp = subprocess.run(["python", str(ROOT / "tools/build_payload.py")], cwd=str(ROOT),
                    env=env, capture_output=True, text=True)
print("[payload]", bp.returncode)
print(bp.stdout[-1500:], bp.stderr[-2000:])
if bp.returncode != 0:
    sys.exit(1)

# 2) bump
g = ROOT / "app/build.gradle.kts"
s = g.read_text(encoding="utf-8")
s = re.sub(r"versionCode\s*=\s*\d+", f"versionCode = {CODE}", s)
s = re.sub(r'versionName\s*=\s*"[^"]*"', f'versionName = "{VER}"', s)
g.write_text(s, encoding="utf-8", newline="\n")
print("[bump]", VER, CODE)

# 3) build
log = ROOT / "v883.log"
with log.open("w", encoding="utf-8", errors="replace") as fh:
    p = subprocess.run([str(ROOT / "gradlew.bat"), ":app:testDebugUnitTest",
                        ":app:assembleRelease", "--console=plain", "--no-daemon"],
                       cwd=str(ROOT), env=env, stdout=fh, stderr=subprocess.STDOUT, text=True)
print("[gradle] rc =", p.returncode)
print("\n".join(log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-6:]))
if p.returncode != 0:
    sys.exit(1)

apk = ROOT / "app/build/outputs/apk/release/app-release.apk"
out = ROOT.parent / f"ExtractKit-{VER}-full.apk"
shutil.copyfile(apk, out)
d = out.read_bytes()
print(f"[apk] {out.name} {len(d)} B sha256={hashlib.sha256(d).hexdigest()}")
