#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""编译 6.1 ghost 链 payload（独立二进制，产物进 assets/payload/ghost/）。"""
import os, subprocess, sys, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "payload", "ghost6.1")
OUT = os.path.join(ROOT, "app", "src", "main", "assets", "payload", "ghost", "cve-2026-98260-uid0-6.1-ghost")
NDK = r"C:/AndroidSdk/android-ndk-r29/toolchains/llvm/prebuilt/windows-x86_64/bin"
CC = os.path.join(NDK, "aarch64-linux-android34-clang.cmd")
STRIP = os.path.join(NDK, "llvm-strip.exe")
SRCS = ["main.c", "map.c", "util.c", "kaslr.c", "rw.c", "race.c", "cred.c"]

def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    cmd = [CC, "-O2", "-static", "-fno-pie", "-no-pie", "-D_GNU_SOURCE",
           "-Wall", "-Wextra", "-Wno-unused-parameter", "-pthread",
           "-I", SRC, "-o", OUT] + [os.path.join(SRC, s) for s in SRCS]
    print(" ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.stdout: print(r.stdout)
    if r.stderr: print(r.stderr)
    if r.returncode != 0:
        print("[!] build failed rc=%d" % r.returncode)
        return r.returncode
    subprocess.run([STRIP, "-s", OUT], check=False)
    data = open(OUT, "rb").read()
    print("[ok] %s  %d B  sha256=%s" % (OUT, len(data), hashlib.sha256(data).hexdigest()))
    return 0

if __name__ == "__main__":
    sys.exit(main())
