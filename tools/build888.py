import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
GRADLE = ROOT / "gradlew.bat"
BUILD = ROOT / "app/build/outputs/apk/release/app-release.apk"
OUT = ROOT.parent / "ExtractKit-8.88-full.apk"
CODE = 188
NAME = "8.88"

gj = ROOT / "app/build.gradle.kts"
src = gj.read_text(encoding="utf-8")
src = re.sub(r"versionCode\s*=\s*\d+", "versionCode = %d" % CODE, src)
src = re.sub(r'versionName\s*=\s*"[^"]*"', 'versionName = "%s"' % NAME, src)
gj.write_text(src, encoding="utf-8", newline="\n")
print("[bump] %d / %s" % (CODE, NAME))

rc = subprocess.call([str(GRADLE), ":app:testDebugUnitTest", ":app:assembleRelease",
                      "--console=plain"], cwd=str(ROOT))
print("[gradle] rc=%d" % rc)
if rc != 0:
    sys.exit(rc)
if not BUILD.exists():
    print("[!] 没有 release 产物")
    sys.exit(2)
data = BUILD.read_bytes()
OUT.write_bytes(data)
print("[ok] %s %d B sha256=%s" % (OUT.name, len(data), hashlib.sha256(data).hexdigest()))
