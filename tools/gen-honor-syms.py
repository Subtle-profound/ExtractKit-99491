#!/usr/bin/env python3
"""gen-honor-syms.py - 从我们自己解包的 arm64 Image 生成 HONOR 链要用的符号表。

流程：boot.img -> tools/unpack-boot.py（或手工按页取出）-> Image
      -> tools/find-kallsyms.py -> kallsyms.txt
      -> 本脚本 -> Kotlin 片段 / honor.map 片段

用法:
    python tools/gen-honor-syms.py kallsyms.txt
    python tools/gen-honor-syms.py kallsyms.txt --release 6.6.89-android15-8-g082e5a98dac1
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

# 与 app/src/main/kotlin/com/extractkit/app/HonorMap.kt 的 NAMES 保持一致
# 9.180 精简：payload 只查 init_cred（honor_ic）与 selinux_state（honor_se）。
NAMES = [
    "init_cred", "selinux_state",
]


def load(path: pathlib.Path) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in path.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        addr, _typ, name = parts[0], parts[1], parts[2]
        if not re.fullmatch(r"[0-9a-fA-F]{8,16}", addr):
            continue
        out.setdefault(name, int(addr, 16))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kallsyms")
    ap.add_argument("--release", default="")
    ap.add_argument("--kotlin", action="store_true", help="打印 Kotlin mapOf 片段")
    ap.add_argument("--map", action="store_true", help="打印 honor.map 片段")
    args = ap.parse_args()

    syms = load(pathlib.Path(args.kallsyms))
    if not syms:
        print("no symbols parsed", file=sys.stderr)
        return 1
    missing = [n for n in NAMES if n not in syms]
    if args.kotlin:
        print("            symbols = mapOf(" if not args.release else "            symbols = mapOf(")
        for n in NAMES:
            v = syms.get(n, 0)
            print(f'                "{n}" to 0x{v:016X}uL.toLong(),')
        print("            ),")
    elif args.map:
        print("# extractkit-map v1")
        print(f"# kernel={args.release or '?'}")
        print(f"# nsyms={sum(1 for n in NAMES if syms.get(n))}")
        for n in NAMES:
            print(f"{n} 0x{syms.get(n, 0):x}")
    else:
        print(f"release={args.release or '?'} parsed={len(syms)}")
        for n in NAMES:
            v = syms.get(n)
            print(f"  {n:22s} {'0x%016x' % v if v else 'MISSING'}")
    if missing:
        print("missing: " + " ".join(missing), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
