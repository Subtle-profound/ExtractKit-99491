#!/usr/bin/env python
"""From-scratch payload build: pristine upstream source, upstream flags, no patches.

Source of truth: payload/clean/src/cve-2026-98260-uid0.c (byte-identical copy of the
upstream tree). Nothing is post-processed: no shims, no string patches, no family
variants. One binary ships for every kernel.

    python tools/build-clean.py
"""
import hashlib, os, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "payload" / "clean" / "src" / "cve-2026-98260-uid0.c"
OUT = ROOT / "app" / "src" / "main" / "assets" / "payload" / "cve-2026-98260-uid0"
CAT = ROOT / "app" / "src" / "main" / "kotlin" / "com" / "extractkit" / "app" / "PayloadCatalog.kt"
SUMS = ROOT / "app" / "src" / "main" / "assets" / "SHA256SUMS.txt"
API = "34"

def ndk_bin():
    cands = [os.environ.get("ANDROID_NDK_HOME"), os.environ.get("NDK"),
             r"C:\AndroidSdk\android-ndk-r29"]
    for c in cands:
        if not c:
            continue
        b = pathlib.Path(c) / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin"
        if (b / "clang.exe").exists():
            return b
    sys.exit("build-clean: NDK not found (set ANDROID_NDK_HOME)")

def main():
    b = ndk_bin()
    cc = b / f"aarch64-linux-android{API}-clang.cmd"
    cc = cc if cc.exists() else b / "clang.exe"
    args = [str(cc), "-O2", "-static", "-fno-pie", "-no-pie", "-D_GNU_SOURCE",
            "-Wall", "-Wextra", "-Wno-unused-parameter", "-pthread",
            f"--target=aarch64-linux-android{API}",
            "-I", str(SRC.parent), "-o", str(OUT), str(SRC)]
    print("[clean] " + " ".join(args[:3]) + " ... -> " + OUT.name)
    r = subprocess.run(args, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("build-clean: clang failed\n" + r.stdout + r.stderr)
    subprocess.run([str(b / "llvm-strip.exe"), str(OUT)], capture_output=True)
    data = OUT.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    print("[clean] size=%d sha256=%s" % (len(data), sha))

    cat = CAT.read_text(encoding="utf-8")
    cat2 = re.sub(r'("payload/cve-2026-98260-uid0",\s*\n\s*")[0-9a-f]{64}', lambda m: m.group(1) + sha, cat, count=1)
    if cat2 == cat:
        sys.exit("build-clean: could not rewrite UID0 sha in PayloadCatalog.kt")
    CAT.write_text(cat2, encoding="utf-8", newline="\n")

    lines = []
    for d in ("payload", "stage", "honor"):
        base = ROOT / "app" / "src" / "main" / "assets" / d
        for f in sorted(base.rglob("*")):
            if f.is_file():
                rel = f.relative_to(ROOT / "app" / "src" / "main" / "assets").as_posix()
                lines.append("%s  %s" % (hashlib.sha256(f.read_bytes()).hexdigest(), rel))
    SUMS.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("[clean] SHA256SUMS.txt %d lines" % len(lines))

main()
