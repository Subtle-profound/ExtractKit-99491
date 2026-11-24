"""编译 5.10 专用 payload（强制 offsets-only），并同步 sha256。"""
import hashlib
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]   # extract-kit/
NDK = pathlib.Path("C:/AndroidSdk/android-ndk-r29")
HOST = "windows-x86_64"
CLANG = NDK / "toolchains/llvm/prebuilt" / HOST / "bin/aarch64-linux-android34-clang.cmd"
SRC = ROOT / "payload/src/cve-2026-98260-uid0.c"
OUT = ROOT / "app/src/main/assets/payload/cve-2026-98260-uid0-510"

cmd = [
    str(CLANG), "-O2", "-static", "-fno-pie", "-no-pie",
    "-D_GNU_SOURCE", "-DFORCE_OFFSETS_ONLY=1",
    "-Wall", "-Wextra", "-Wno-unused-parameter", "-pthread",
    "-I", str(SRC.parent), "-o", str(OUT), str(SRC),
]
print("[build]", OUT.name)
p = subprocess.run(cmd, capture_output=True, text=True)
for stream in (p.stdout, p.stderr):
    if stream.strip():
        print(stream.strip())
if p.returncode != 0:
    sys.exit(f"compile failed rc={p.returncode}")

strip = NDK / "toolchains/llvm/prebuilt" / HOST / "bin/llvm-strip.exe"
subprocess.run([str(strip), "-s", str(OUT)], capture_output=True, text=True)

data = OUT.read_bytes()
sha = hashlib.sha256(data).hexdigest()
print(f"[ok] {len(data)} B sha256={sha}")

cat = ROOT / "app/src/main/kotlin/com/extractkit/app/PayloadCatalog.kt"
text = cat.read_text(encoding="utf-8")
new, n = re.subn(r'(?s)(val OFF510 = Payload\(\s*"cve-2026-98260-uid0-510",\s*"payload/cve-2026-98260-uid0-510",\s*")[0-9a-f]{64}(")',
                 lambda m: m.group(1) + sha + m.group(2), text, count=1)
if n != 1:
    sys.exit("catalog OFF510 sha not replaced")
cat.write_text(new, encoding="utf-8", newline="\n")
print("[catalog] OFF510 updated")

sums = ROOT / "app/src/main/assets/SHA256SUMS.txt"
lines = [l for l in sums.read_text(encoding="utf-8").splitlines() if "cve-2026-98260-uid0-510" not in l]
lines.append(f"{sha}  payload/cve-2026-98260-uid0-510")
sums.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
print("[sums] updated")
