"""用 NDK 编译 uid0 payload（Windows 下不经 bash），并同步 sha256。"""
import hashlib
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
NDK = pathlib.Path("C:/AndroidSdk/android-ndk-r29")
HOST = "windows-x86_64"
CLANG = NDK / "toolchains/llvm/prebuilt" / HOST / "bin/aarch64-linux-android34-clang.cmd"
SRC = ROOT / "payload/src/cve-2026-98260-uid0.c"
# 9.195：字面版也有自己的单支源（条件编译已展开），改它只改这个文件。
SPLIT = ROOT / "payload/src/fam/literal.c"
OUT = ROOT / "app/src/main/assets/payload/cve-2026-98260-uid0"

if SPLIT.is_file():
    src = SPLIT
    fam_flags = []
    print("[src] literal: payload/src/fam/literal.c")
else:
    src = SRC
    # 字面版就是 6.6.118 那台机器标定出来的，显式标成 6.6（606）：
    # 以前不传任何族宏，payload 里 [payload] family=generic，日志看不出它属于哪一族。
    fam_flags = ['-DEXTRACTKIT_FAMILY_ID="6.6"', "-DEXTRACTKIT_FAMILY_INT=606"]
    print("[src] literal: 主源 + -D（未找到 payload/src/fam/literal.c）")

cmd = [
    str(CLANG), "-O2", "-static", "-fno-pie", "-no-pie",
    "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Wno-unused-parameter", "-pthread",
] + fam_flags + [
    "-I", str(SRC.parent), "-o", str(OUT), str(src),
] + [f for f in os.environ.get("EXTRA_CFLAGS", "").split() if f]
print("[build]", CLANG.name, "->", OUT.name)
p = subprocess.run(cmd, capture_output=True, text=True)
if p.stdout.strip():
    print(p.stdout.strip())
if p.stderr.strip():
    print(p.stderr.strip())
if p.returncode != 0:
    sys.exit(f"compile failed rc={p.returncode}")

strip = NDK / "toolchains/llvm/prebuilt" / HOST / "bin/llvm-strip.exe"
s = subprocess.run([str(strip), "-s", str(OUT)], capture_output=True, text=True)
if s.returncode != 0:
    print("[warn] llvm-strip:", s.stderr.strip()[:300])

data = OUT.read_bytes()
sha = hashlib.sha256(data).hexdigest()
print(f"[ok] {len(data)} B sha256={sha}")

# 1) PayloadCatalog.kt 里的 UID0.sha256
cat = ROOT / "app/src/main/kotlin/com/extractkit/app/PayloadCatalog.kt"
text = cat.read_text(encoding="utf-8")
# 9.192：原来按 id = "chain_uid0" 定位（Mode 里没有 sha256，早就匹配不到），
# 回落分支又是「文本里第一个 64 位十六进制串」，两处都脆 —— 本次就误改到了
# "5.10" 的 PER_FAMILY 哈希上。现在只锚「UID0 的资源路径下一行那个 64 位哈希」。
pat = r'("payload/cve-2026-98260-uid0",\s*")[0-9a-f]{64}(")'
new, n = re.subn(pat, lambda m: m.group(1) + sha + m.group(2), text, count=1)
if n != 1:
    sys.exit(f"[catalog] UID0 asset line not found (n={n}), refuse to guess")
cat.write_text(new, encoding="utf-8", newline="\n")
print("[catalog] updated", n)

# 2) assets/SHA256SUMS.txt
sums = ROOT / "app/src/main/assets/SHA256SUMS.txt"
lines = []
if sums.exists():
    for line in sums.read_text(encoding="utf-8").splitlines():
        # 只跳过「字面版自己」那一行：fam 六支的文件名也含这个前缀，
        # 原来用 in 判断会把 6 支的 sums 行一起删掉（9.192 修正）。
        if line.split()[-1] == "payload/cve-2026-98260-uid0":
            continue
        lines.append(line)
lines.append(f"{sha}  payload/cve-2026-98260-uid0")
sums.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
print("[sums] updated")
