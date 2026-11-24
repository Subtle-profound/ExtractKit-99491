#!/usr/bin/env python3
"""ghostlock-conf.py - 用我们自己解出来的 kallsyms / HAPT profile 生成 GhostLock 内核配置。

GhostLock 的已适配内核清单在 MapleSU 包里：
  assets/ghostlock/index.conf          -> profiles = [ { release, file } ]，release 必须与 uname -r 全串一致
  assets/ghostlock/<release>.conf      -> 单内核配置（HOCON）
运行时 App 把 conf 转成 GLK1 二进制经 stdin 交给 libmaplesu_ghostlock_provider.so。

本脚本产出上表第二件（<release>.conf）与一条 index 条目。offset{} 的语义已从 6.12-template.conf
的注释实锤：全部是"相对内核镜像基址（默认 0xffffffc080000000）的偏移"，不是绝对地址。

映射（符号 -> 配置键）：
  init_task            -> init_task
  init_cred            -> init_cred
  root_task_group      -> root_task_group
  selinux_state(+0)    -> selinux_enforcing      （selinuxEnforcing 偏移来自 HAPT profile / BTF）
  selinux_blob_sizes   -> selinux_blob_sizes
  security_hook_heads  -> security_hook_heads    （缺失写 0，参考 6.12.23 那份就是 0）
  nfulnl_logger        -> slide_nfulnl_logger
  sysctl_bootid        -> slide_boot_id
  loggers              -> slide_loggers_0_1

用法：
  python tools/ghostlock-conf.py --release "<真机 uname -r>" \
      --kallsyms kallsyms.txt --template <同大版本参考 conf> --out outdir
  python tools/ghostlock-conf.py --release "..." --hapt <profile.json> --template ...
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

BASE_DEFAULT = 0xFFFFFFC080000000

# 配置键 -> kallsyms 符号候选（按顺序取第一个命中的）
SYM_MAP = {
    "init_task": ["init_task"],
    "init_cred": ["init_cred"],
    "root_task_group": ["root_task_group"],
    "selinux_blob_sizes": ["selinux_blob_sizes"],
    "security_hook_heads": ["security_hook_heads"],
    "slide_nfulnl_logger": ["nfulnl_logger"],
    "slide_boot_id": ["sysctl_bootid"],
    "slide_loggers_0_1": ["loggers"],
}
REQUIRED = [
    "init_task", "init_cred", "root_task_group", "selinux_enforcing",
    "selinux_blob_sizes", "slide_nfulnl_logger", "slide_boot_id", "slide_loggers_0_1",
]


def load_kallsyms(path: pathlib.Path) -> dict[str, int]:
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


def load_hapt(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def extract_block(text: str, key: str) -> str:
    """取出 text 里第一个 "key { ... }" 整块（花括号计数，能处理嵌套）。"""
    m = re.search(r"(?m)^\s*" + re.escape(key) + r"\s*\{", text)
    if not m:
        return ""
    start = m.start()
    i = text.index("{", m.start())
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start:j + 1].strip()
    return ""


def extract_scalar(text: str, key: str) -> str:
    m = re.search(r"(?m)^\s*" + re.escape(key) + r"\s*=\s*(.+?)\s*$", text)
    return m.group(1) if m else ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", required=True, help="真机 uname -r 全串（必须逐字一致）")
    ap.add_argument("--kallsyms", help="tools/find-kallsyms.py 解出的 kallsyms.txt")
    ap.add_argument("--hapt", help="HAPT 服务器下发的 profile.json（补 selinux_enforcing / task_struct）")
    ap.add_argument("--base", default=hex(BASE_DEFAULT), help="内核镜像基址，默认 0xffffffc080000000")
    ap.add_argument("--template", help="同大版本的参考 conf，用来继承 task_struct / route / fallback / include")
    ap.add_argument("--out", default=".", help="输出目录")
    args = ap.parse_args()

    base = int(args.base, 16)
    syms = load_kallsyms(pathlib.Path(args.kallsyms)) if args.kallsyms else {}
    hapt = load_hapt(pathlib.Path(args.hapt)) if args.hapt else {}

    vals: dict[str, int] = {}
    missing: list[str] = []

    for key, cands in SYM_MAP.items():
        for name in cands:
            if name in syms:
                vals[key] = (syms[name] - base) & 0xFFFFFFFFFFFFFFFF
                break
        else:
            missing.append(key)

    # selinux_enforcing = selinux_state + offsetof(selinux_state, enforcing)
    enf_off = 0
    if "offsets" in hapt and isinstance(hapt["offsets"].get("selinuxEnforcing"), int):
        enf_off = hapt["offsets"]["selinuxEnforcing"]
    state = None
    if "selinux_state" in syms:
        state = syms["selinux_state"]
    elif "symbols" in hapt and hapt["symbols"].get("selinux_state"):
        state = int(hapt["symbols"]["selinux_state"], 16)
    if state is None:
        missing.append("selinux_enforcing")
    else:
        vals["selinux_enforcing"] = (state + enf_off - base) & 0xFFFFFFFFFFFFFFFF

    if "security_hook_heads" in missing:
        # 参考实现允许 0：6.12.23 那份 conf 里 security_hook_heads = 0
        vals["security_hook_heads"] = 0
        missing = [m for m in missing if m != "security_hook_heads"]

    # task_struct：优先用模板继承，其次用 HAPT 的三项
    task_tpl = ""
    tpl_text = ""
    if args.template:
        tpl_text = pathlib.Path(args.template).read_text(encoding="utf-8", errors="replace")
        m = re.search(r"task_struct\s*\{(.*?)\}", tpl_text, re.S)
        if m:
            task_tpl = m.group(0)

    lines: list[str] = []
    lines.append("# GhostLock kernel profile: %s (HOCON)." % args.release)
    lines.append("# 由 extract-kit tools/ghostlock-conf.py 生成；offset 均为相对镜像基址 %#x 的偏移。" % base)
    lines.append('include "credential-6x.conf"')
    lines.append('include "kernelsnitch-6x.conf"')
    lines.append('release = "%s"' % args.release)
    lines.append("schema_version = 1")
    # 这几项与内核 build 无关，但 6.6/6.12 家族各 build 略有差别 -> 优先从模板继承
    for key, dflt in [("kernel_major", "6"), ("recommend_shizuku", "0"),
                      ("kernel_phys_load", "null"), ("kernel_phys_offset", "null")]:
        v = extract_scalar(tpl_text, key) if tpl_text else ""
        lines.append("%s = %s" % (key, v or dflt))
    route_tpl = extract_block(tpl_text, "route") if tpl_text else ""
    lines.append(route_tpl or "route {")
    if not route_tpl:
        lines.append("  select_stack {")
        lines.append("    waiter_shift = -2")
        lines.append("  }")
        lines.append("}")
    fallback_tpl = extract_block(tpl_text, "fallback") if tpl_text else ""
    lines.append(fallback_tpl or 'fallback {')
    if not fallback_tpl:
        lines.append('  to = "none"')
        lines.append("}")
    if task_tpl:
        lines.append(task_tpl)
    lines.append("offset {")
    lines.append("  empty_zero_page = null")
    for key in ["init_task", "init_cred", "root_task_group", "selinux_enforcing",
                "selinux_blob_sizes", "security_hook_heads", "slide_nfulnl_logger",
                "slide_boot_id", "slide_loggers_0_1"]:
        if key in vals:
            lines.append("  %s = %d" % (key, vals[key]))
        else:
            lines.append("  %s = null" % key)
    lines.append("}")
    text = "\n".join(lines) + "\n"

    outdir = pathlib.Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    conf = outdir / (args.release + ".conf")
    conf.write_text(text, encoding="utf-8", newline="\n")

    print("release  =", args.release)
    print("base     =", hex(base))
    print("conf     =", conf, "(%d bytes)" % conf.stat().st_size)
    print("index    = { release = \"%s\", file = \"%s.conf\" }" % (args.release, args.release))
    for key in ["init_task", "init_cred", "root_task_group", "selinux_enforcing",
                "selinux_blob_sizes", "security_hook_heads", "slide_nfulnl_logger",
                "slide_boot_id", "slide_loggers_0_1"]:
        if key in vals:
            print("  %-20s %10d  (%#x)" % (key, vals[key], vals[key]))
    if not task_tpl:
        print("! task_struct 未填充：用 --template 指向一份同大版本的参考 conf 继承")
    if missing:
        print("! 缺 %d 项：%s" % (len(missing), ", ".join(missing)))
        print("! 这些必须来自该内核自己的 Image/kallsyms（boot.img -> tools/find-kallsyms.py）")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
