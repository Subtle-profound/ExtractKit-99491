import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
GRADLE = ROOT / "gradlew.bat"
BUILD = ROOT / "app/build/outputs/apk/release/app-release.apk"
OUT = ROOT.parent / "ExtractKit-8.87-full.apk"

gj = ROOT / "app/build.gradle.kts"
src = gj.read_text(encoding="utf-8")
src = re.sub(r"versionCode\s*=\s*\d+", "versionCode = 187", src)
src = re.sub(r'versionName\s*=\s*"[^"]*"', 'versionName = "8.87"', src)
gj.write_text(src, encoding="utf-8", newline="\n")
print("[bump] 187 / 8.87")

cmd = [str(GRADLE), ":app:testDebugUnitTest", ":app:assembleRelease", "--console=plain"]
rc = subprocess.call(cmd, cwd=str(ROOT))
print("[gradle] rc=%d" % rc)
if rc != 0:
    sys.exit(rc)
if not BUILD.exists():
    print("[!] 没有 release 产物")
    sys.exit(2)
data = BUILD.read_bytes()
OUT.write_bytes(data)
print("[ok] %s %d B sha256=%s" % (OUT.name, len(data), hashlib.sha256(data).hexdigest()))
