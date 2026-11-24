"""三个分支链路与上游 CVE-2026-99491-FANXIAOCHAO 的逐函数比对。

用法::

    python tools/parity-expc.py            # 摘要表
    python tools/parity-expc.py --hunks    # 逐 hunk

上游副本：refdata/_up99491_clean/CVE-2026-99491-FANXIAOCHAO-main/src
本地：    refdata/eksu-chain/src
比对前会去掉注释、空白，并把 CVE99491/cve99491 归一成 EKSU/eksu，
这样剩下的差异才是真正的代码差异。
"""
import difflib
import re
import sys

UP = r"D:\deepseek work\refdata\_up99491_clean\CVE-2026-99491-FANXIAOCHAO-main\src\exp.c"
OUR = r"D:\deepseek work\refdata\eksu-chain\src\exp.c"

FUNC = re.compile(r"^(?:static\s+)?(?:inline\s+)?(?:unsigned\s+|signed\s+|const\s+|struct\s+\w+\s+)?[\w \*]+?\b(\w+)\s*\([^;{]*$")


def strip(src):
    src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.S)
    return re.sub(r"//[^\n]*", "", src)


def funcs(path):
    lines = strip(open(path, encoding="utf-8", errors="replace").read()).splitlines()
    out, i, n = {}, 0, len(lines)
    while i < n:
        m = FUNC.match(lines[i].rstrip())
        if m and (lines[i].rstrip().endswith("{") or lines[i].rstrip().endswith(",")):
            j, sig = i, ""
            while j < n and "{" not in lines[j]:
                sig += lines[j] + "\n"
                j += 1
            if j >= n:
                break
            name = m.group(1)
            k, d, body = j, 0, []
            while k < n:
                body.append(lines[k])
                d += lines[k].count("{") - lines[k].count("}")
                if d == 0:
                    break
                k += 1
            out[name] = [b for b in (re.sub(r"\s+", " ", x).strip() for x in body) if b]
            i = k + 1
            continue
        i += 1
    return out


def norm(d):
    def fix(s):
        return s.replace("CVE99491", "EKSU").replace("cve99491", "eksu")
    return {fix(k): [fix(x) for x in v] for k, v in d.items()}


a, b = norm(funcs(UP)), norm(funcs(OUR))
print("upstream funcs", len(a), " local funcs", len(b))
print("only upstream:", sorted(set(a) - set(b)))
print("only local   :", sorted(set(b) - set(a)))
diff = []
for k in sorted(set(a) & set(b)):
    if a[k] != b[k]:
        sm = difflib.SequenceMatcher(None, a[k], b[k], autojunk=False)
        ch = [o for o in sm.get_opcodes() if o[0] != "equal"]
        diff.append((k, len(a[k]), len(b[k]), ch))
print("\ndiffering functions:", len(diff))
for k, la, lb, ch in diff:
    print("  %-26s up=%4d local=%4d hunks=%d" % (k, la, lb, len(ch)))
if "--hunks" in sys.argv:
    for k, la, lb, ch in diff:
        print("\n########", k)
        for t, i1, i2, j1, j2 in ch:
            print(" --", t, "up[%d:%d] local[%d:%d]" % (i1, i2, j1, j2))
            for l in a[k][max(0, i1 - 1):i2 + 1]:
                print("   - " + l[:200])
            for l in b[k][max(0, j1 - 1):j2 + 1]:
                print("   + " + l[:200])