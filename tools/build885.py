import re, subprocess, sys, pathlib, hashlib, shutil

ROOT = pathlib.Path(r"C:\Users\Admin\Documents\deepseek-harness\default-workspace\extract-kit")
WS = ROOT.parent


def run(cmd, cwd=ROOT):
    print(">>", " ".join(cmd))
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, shell=False)
    out = (p.stdout or "") + (p.stderr or "")
    print(out[-3000:])
    return p.returncode


def bump():
    g = ROOT / "app/build.gradle.kts"
    s = g.read_text(encoding="utf-8")
    s = re.sub(r"versionCode = \d+", "versionCode = 185", s)
    s = re.sub(r'versionName = "[^"]*"', 'versionName = "8.85"', s)
    g.write_text(s, encoding="utf-8", newline="\n")
    print("bumped to 8.85 / 185")


bump()
if run([sys.executable, str(ROOT / "tools/build_payload.py")]) != 0:
    sys.exit("payload build failed")
if run(["cmd.exe", "/c", "gradlew.bat :app:testDebugUnitTest :app:assembleRelease --console=plain"]) != 0:
    sys.exit("gradle failed")

src = ROOT / "app/build/outputs/apk/release/app-release.apk"
dst = WS / "ExtractKit-8.85-full.apk"
shutil.copyfile(src, dst)
data = dst.read_bytes()
print("apk", dst.name, len(data), hashlib.sha256(data).hexdigest())
