#!/usr/bin/env python3
"""check-split.py —— 校验 payload/src/fam/*.c 七份单支源自洽。

9.195 起每支 payload 一个独立 .c（tools/split-fam.py 生成），改一支只改那个文件。
这个检查器只做静态自检，不编译：
  1. 七份文件都在，且文件头写了自己那一族的 EXTRACTKIT_FAMILY_ID / _INT / _CHAIN
  2. 文件里不再残留按链分叉的条件编译（EXTRACTKIT_CHAIN 比较、chain_*.c 的 #include）
  3. 每份都能编（粗略）：不出现 "#error"
  4. build_fam.py / build_payload.py 确实优先编 fam/ 目录（SPLIT_DIR 引用存在）
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAM = ROOT / "payload/src/fam"

# chain 号 -> 链实现文件名（与 payload/src/chain_sel.h 的 CHAIN_* 一致）。
# CHAIN_LEGACY（0）没有独立文件，实现内联在主源里，所以它要求「不 include 任何链文件」。
CHAIN_FILE = {0: None, 1: "chain_honor.c", 2: "chain_brm.c", 3: "chain_k618.c"}

# 文件 id -> (FAMILY_ID, FAMILY_INT, CHAIN)
EXPECT = {
    "510": ("5.10", 510, 1),
    "515": ("5.15", 515, 1),
    "61": ("6.1", 601, 2),
    "66": ("6.6", 606, 0),
    "612": ("6.12", 612, 0),
    "618": ("6.18", 618, 3),
    "literal": ("6.6", 606, 0),
}


def main():
    bad = []
    for fid, (fname, fint, chain) in EXPECT.items():
        p = FAM / (fid + ".c")
        if not p.is_file():
            bad.append(f"{fid}: 缺文件 {p}（先跑 python tools/split-fam.py）")
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        head = "\n".join(text.splitlines()[:40])
        for want in (
            f'#define EXTRACTKIT_FAMILY_ID "{fname}"',
            f"#define EXTRACTKIT_FAMILY_INT {fint}",
            f"#define EXTRACTKIT_CHAIN {chain}",
        ):
            if want not in head:
                bad.append(f"{fid}: 文件头缺 {want}")
        if fid != "literal" and f'#define EXPECT_FAMILY "{fname}."' not in head:
            bad.append(f'{fid}: 文件头缺 #define EXPECT_FAMILY "{fname}."')
        if fid == "literal" and "EXPECT_FAMILY" in head:
            bad.append(f"{fid}: 字面版不应定义 EXPECT_FAMILY")
        # 条件编译不该残留（#include 保护用的 #ifndef 头文件宏不算）。
        # 但链实现文件的 include 必须留且只留自己那一条：split 只是把
        # #if EXTRACTKIT_CHAIN == X / #include "chain_X.c" 收敛成无条件 include。
        for pat in ("EXTRACTKIT_CHAIN ==", "EXTRACTKIT_CHAIN==", "#error"):
            if pat in text:
                bad.append(f"{fid}: 仍残留 {pat}")
        for other_chain, other in CHAIN_FILE.items():
            if not other:
                continue
            here = f'#include "{other}"' in text
            if other_chain == chain and not here:
                bad.append(f"{fid}: 缺 {other} 的 include")
            if other_chain != chain and here:
                bad.append(f"{fid}: 多出别条链的 include {other}")
        if "split-fam.py" not in head:
            bad.append(f"{fid}: 文件头缺「由 split-fam.py 生成」的说明")

    for name, needle in (("build_fam.py", "payload/src/fam"),
                         ("build_payload.py", "payload/src/fam/literal.c")):
        p = ROOT / "tools" / name
        if not p.is_file() or needle not in p.read_text(encoding="utf-8", errors="replace"):
            bad.append(f"{name}: 未引用 {needle}")

    if bad:
        print("[fail] split sources:")
        for b in bad:
            print("   " + b)
        return 1
    print(f"[ok] split sources: {len(EXPECT)} 份单支源自洽，build 脚本已指向 fam/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
