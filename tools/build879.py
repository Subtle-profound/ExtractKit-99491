"""bump 到 8.79 并出 release 包。"""
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
VER, CODE = "8.79", 179

g = ROOT / "app/build.gradle.kts"
s = g.read_text(encoding="utf-8")
s = re.sub(r"versionCode\s*=\s*\d+", f"versionCode = {CODE}", s)
s = re.sub(r'versionName\s*=\s*"[^"]*"', f'versionName = "{VER}"', s)
g.write_text(s, encoding="utf-8", newline="\n")
print("[bump]", VER, CODE)

env = dict(os.environ)
env["JAVA_HOME"] = r"C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot"
env["GRADLE_OPTS"] = "-Dorg.gradle.jvmargs=-Xmx3g"

log = ROOT / "v879.log"
with log.open("w", encoding="utf-8", errors="replace") as fh:
    p = subprocess.run(
        [str(ROOT / "gradlew.bat"), ":app:testDebugUnitTest", ":app:assembleRelease",
         "--console=plain", "--no-daemon"],
        cwd=str(ROOT), env=env, stdout=fh, stderr=subprocess.STDOUT, text=True,
    )
print("[gradle] rc =", p.returncode)
tail = log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-12:]
print("\n".join(tail))
if p.returncode != 0:
    sys.exit(1)

apk = ROOT / "app/build/outputs/apk/release/app-release.apk"
out = ROOT.parent / f"ExtractKit-{VER}-full.apk"
shutil.copyfile(apk, out)
data = out.read_bytes()
print(f"[apk] {out.name} {len(data)} B sha256={hashlib.sha256(data).hexdigest()}")
