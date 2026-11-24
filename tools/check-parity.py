#!/usr/bin/env python3
"""按链比对「观测面」：参考 payload 里出现的 tag / PC98260_* 开关 / --选项，
必须全部出现在我们对应族的产物里（coverage 100% 才算过）。

用法： python tools/check-parity.py [--refdir DIR]
默认 refdir = 仓库父目录下的 refdata（D:\\deepseek work\\refdata）。
参考文件缺失时打 SKIP 并 exit 0（参考二进制不进仓库）。
"""
import argparse
import os
import re
import sys

# 链 -> (参考文件名, 产物族)
CASES = [
    ("honor", "ref_510_libsysopt", ["5.10", "5.15"]),
    ("brm", "ref_61_brm_plant", ["6.1"]),
    ("k618", "ref_618_keyptr", ["6.18"]),
]

FAM_DIR = os.path.join("app", "src", "main", "assets", "payload", "fam")
FAM_FILE = "cve-2026-98260-uid0-%s"

# 参考二进制里的 printf / 链接器内部残留，不是我们的日志 tag
IGNORE_TAGS = {"[2]"}

TAG_RE = re.compile(rb"\[[a-zA-Z0-9_.-]+\]")
UAF_RE = re.compile(rb"UAF-[A-Za-z0-9.-]+")
ENV_RE = re.compile(rb"PC98260_[A-Z0-9_]+")
OPT_RE = re.compile(rb"--[a-z][a-z0-9-]{2,}")
KEY_RE = re.compile(rb"(?:^|[\x00\s;])([a-z][a-z_]{2,15})=")


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


def surface(blob, uaf_only=False):
    # honor 链的观测面是 UAF-* 前缀；brm/k618 链是 [tag] 前缀。
    tags = set(m.group().decode() for m in UAF_RE.finditer(blob))
    if not uaf_only:
        tags |= set(m.group().decode() for m in TAG_RE.finditer(blob))
    envs = set(m.group().decode() for m in ENV_RE.finditer(blob))
    opts = set(m.group().decode() for m in OPT_RE.finditer(blob))
    # 参考实现里有 PC98260_FINIT__ 这类字符串拼接残留，不算真开关
    envs = set(e for e in envs if not e.endswith("__"))
    return tags, envs, opts


def key_names(blob):
    return set(m.group(1).decode() for m in KEY_RE.finditer(blob))


def tokens(blob):
    out = set()
    for word in re.finditer(rb"[a-z][a-z_]{2,15}", blob):
        out.add(word.group().decode())
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--refdir", default=os.path.join("..", "refdata"))
    args = ap.parse_args()

    fails = 0
    for chain, refname, fams in CASES:
        ref = os.path.join(args.refdir, refname)
        if not os.path.exists(ref):
            print("[skip] %-6s 缺参考 %s" % (chain, ref))
            continue
        rtags, renvs, ropts = surface(read(ref), uaf_only=(chain == "honor"))
        rkeys = key_names(read(ref)) if chain == "honor" else set()
        for fam in fams:
            path = os.path.join(FAM_DIR, FAM_FILE % fam)
            if not os.path.exists(path):
                print("[fail] %-6s 缺产物 %s" % (chain, path))
                fails += 1
                continue
            blob = read(path)
            otags, oenvs, oopts = surface(blob, uaf_only=(chain == "honor"))
            miss_tags = sorted(t for t in rtags - otags if t not in IGNORE_TAGS)
            miss_env = sorted(renvs - oenvs)
            miss_opt = sorted(ropts - oopts)
            miss_key = []
            if rkeys:
                tok = tokens(blob)
                miss_key = sorted(k for k in rkeys if k not in tok)
            total = len(rtags) + len(renvs) + len(ropts) + len(rkeys)
            bad = len(miss_tags) + len(miss_env) + len(miss_opt) + len(miss_key)
            cov = 0.0 if total == 0 else 100.0 * (total - bad) / total
            state = "ok" if bad == 0 else "fail"
            print("[%s] %-6s %-5s coverage=%.1f%% tags=%d env=%d opt=%d key=%d"
                  % (state, chain, fam, cov, len(otags), len(oenvs), len(oopts), len(rkeys)))
            if miss_tags:
                print("        missing tags:", miss_tags)
            if miss_env:
                print("        missing env:", miss_env)
            if miss_opt:
                print("        missing opt:", miss_opt)
            if miss_key:
                print("        missing key:", miss_key)
            if bad:
                fails += 1
    if fails:
        print("[fail] parity coverage 未达 100%%：%d 项" % fails)
        return 1
    print("[ok] parity coverage 100%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
