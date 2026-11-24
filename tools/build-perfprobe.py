#!/usr/bin/env python3
"""build-perfprobe.py - build our own perfprobe target with the NDK.

The reference package ships a 702,304 B static glibc binary whose real logic is
152 bytes of main.  payload/src/perfprobe.c is that logic rewritten as source;
this script compiles it to app/src/main/assets/payload/honor/perfprobe.
"""
import os, subprocess, sys, hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NDK = os.environ.get("NDK_HOME", r"C:/AndroidSdk/android-ndk-r29")
CC = os.path.join(NDK, "toolchains", "llvm", "prebuilt",
                  "windows-x86_64" if os.name == "nt" else "linux-x86_64",
                  "bin", "aarch64-linux-android31-clang.cmd" if os.name == "nt"
                  else "aarch64-linux-android31-clang")
SRC = os.path.join(ROOT, "payload", "src", "perfprobe.c")
OUT = os.path.join(ROOT, "app", "src", "main", "assets", "payload", "honor",
                   "perfprobe")


def main():
    cc = CC if os.path.exists(CC) else CC.replace(".cmd", "")
    cmd = [cc, "-O2", "-static", "-s", "-o", OUT, SRC]
    print("[cc]", " ".join(cmd))
    r = subprocess.run(cmd)
    if r.returncode:
        raise SystemExit("compile failed")
    data = open(OUT, "rb").read()
    print("[ok] %s %d B sha256=%s" % (OUT, len(data),
                                      hashlib.sha256(data).hexdigest()))


if __name__ == "__main__":
    main()
