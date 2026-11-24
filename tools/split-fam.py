"""tools/split-fam.py - 把「一个主源 + 条件编译」展开成「一支一份 .c」（9.195）

主源 payload/src/cve-2026-98260-uid0.c 用 EXTRACTKIT_CHAIN / EXTRACTKIT_FAMILY_INT
等宏切出 6 支 + 字面版。改一支要在一堆 #if 里找，容易改到别的族。

本工具用真预处理器（clang -E -dM）取宏表，再逐行消解条件指令，生成：
    payload/src/fam/510.c  5.10      （honor-uaf 链）
    payload/src/fam/515.c  5.15      （honor-uaf 链）
    payload/src/fam/61.c   6.1       （brm-plant 链）
    payload/src/fam/66.c   6.6       （legacy 链）
    payload/src/fam/612.c  6.12      （legacy 链）
    payload/src/fam/618.c  6.18      （keyptr-618 链）
    payload/src/fam/literal.c 字面版（6.6 标定，无 EXPECT_FAMILY）

生成物是「纯展开」：所有条件指令消失，只留这一支的代码原文，
族/链宏写在文件头。验收标准是重编后与工具化前的产物逐字节相同。

用法：
    python tools/split-fam.py              # 全量重新生成
    python tools/split-fam.py --fam 6.6    # 只生成一支
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "payload/src/cve-2026-98260-uid0.c"
OUTDIR = ROOT / "payload/src/fam"
NDK = pathlib.Path("C:/AndroidSdk/android-ndk-r29")
BIN = NDK / "toolchains/llvm/prebuilt/windows-x86_64/bin"
CLANG = BIN / "aarch64-linux-android34-clang.cmd"

# 族 -> (文件 id, FAMILY_ID 字符串, family int, chain, EXPECT_FAMILY 前缀)
# 注意字面版的 FAMILY_ID 仍是 "6.6"（它就是 6.6 那台标定出来的），
# 只是文件名叫 literal.c、不设 EXPECT_FAMILY 闸门。
FAMS = {
    "5.10": ("510", "5.10", 510, 1, "5.10."),
    "5.15": ("515", "5.15", 515, 1, "5.15."),
    "6.1": ("61", "6.1", 601, 2, "6.1."),
    "6.6": ("66", "6.6", 606, 0, "6.6."),
    "6.12": ("612", "6.12", 612, 0, "6.12."),
    "6.18": ("618", "6.18", 618, 3, "6.18."),
    "literal": ("literal", "6.6", 606, 0, None),
}

PROBE_HEADERS = ["device_config.h", "family_defaults.h", "runtime_cfg.h", "chain_sel.h"]

# 6.6 走「只改 task->cred」策略（与 9.192 同）：不写 real_cred，verify 放行
# 交给后面的 ksud late-load 判定。其余族照旧双写。
NO_REAL_CRED = {"6.6": 1}

TOKEN = re.compile(
    r"\s*(defined|0[xX][0-9a-fA-F]+|\d+|[A-Za-z_]\w*|&&|\|\||==|!=|<=|>=|[!<>()+\-])")


def seed_macros(fam, num, chain, expect):
    """取一份和真编译一致的宏表（含头文件里定义的那些）。"""
    probe = OUTDIR.parent / "_split_probe.c"
    body = "".join('#include "%s"' % h + chr(10) for h in PROBE_HEADERS)
    probe.write_text(body, encoding="utf-8", newline=chr(10))
    cmd = [str(CLANG), "-E", "-dM", "-D_GNU_SOURCE",
           '-DEXTRACTKIT_FAMILY_ID="%s"' % fam,
           "-DEXTRACTKIT_FAMILY_INT=%d" % num,
           "-DEXTRACTKIT_CHAIN=%d" % chain,
           "-I", str(SRC.parent), str(probe)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("[probe] clang failed: " + (p.stderr or "").strip()[:400])
    macros = {}
    for line in p.stdout.splitlines():
        m = re.match(r"#define\s+([A-Za-z_]\w*)\s+(.*)$", line)
        if m:
            macros[m.group(1)] = m.group(2).strip()
    if expect:
        macros["EXPECT_FAMILY"] = '"%s"' % expect
    return macros


def macro_num(name, macros, depth=0):
    if name not in macros or depth > 32:
        return 0
    val = macros[name].strip()
    val = re.sub(r"(?i)(u|ul|ull|l|ll)$", "", val)
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", val):
        return int(val, 16)
    if re.fullmatch(r"\d+", val):
        return int(val)
    if re.fullmatch(r"[A-Za-z_]\w*", val):
        return macro_num(val, macros, depth + 1)
    return 0


class P:
    def __init__(self, tokens, macros):
        self.t = tokens
        self.i = 0
        self.m = macros

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def eat(self, want=None):
        tok = self.peek()
        if tok is None:
            raise ValueError("eof")
        if want is not None and tok != want:
            raise ValueError("want %s got %s" % (want, tok))
        self.i += 1
        return tok

    def parse_or(self):
        v = self.parse_and()
        while self.peek() == "||":
            self.eat()
            r = self.parse_and()
            v = 1 if (v or r) else 0
        return v

    def parse_and(self):
        v = self.parse_eq()
        while self.peek() == "&&":
            self.eat()
            r = self.parse_eq()
            v = 1 if (v and r) else 0
        return v

    def parse_eq(self):
        v = self.parse_rel()
        while self.peek() in ("==", "!="):
            op = self.eat()
            r = self.parse_rel()
            v = 1 if ((v == r) if op == "==" else (v != r)) else 0
        return v

    def parse_rel(self):
        v = self.parse_add()
        while self.peek() in ("<", ">", "<=", ">="):
            op = self.eat()
            r = self.parse_add()
            v = 1 if {"<": v < r, ">": v > r, "<=": v <= r, ">=": v >= r}[op] else 0
        return v

    def parse_add(self):
        v = self.parse_unary()
        while self.peek() in ("+", "-"):
            op = self.eat()
            r = self.parse_unary()
            v = v + r if op == "+" else v - r
        return v

    def parse_unary(self):
        tok = self.peek()
        if tok == "!":
            self.eat()
            return 0 if self.parse_unary() else 1
        if tok == "-":
            self.eat()
            return -self.parse_unary()
        if tok == "(":
            self.eat()
            v = self.parse_or()
            self.eat(")")
            return v
        if tok == "defined":
            self.eat()
            if self.peek() == "(":
                self.eat()
                name = self.eat()
                self.eat(")")
            else:
                name = self.eat()
            return 1 if name in self.m else 0
        if tok is None:
            raise ValueError("eof in expr")
        self.eat()
        if re.fullmatch(r"0[xX][0-9a-fA-F]+|\d+", tok):
            return int(tok, 0)
        return macro_num(tok, self.m)


def eval_expr(expr, macros):
    tokens = []
    pos = 0
    while pos < len(expr):
        m = TOKEN.match(expr, pos)
        if not m:
            if expr[pos:].strip() == "":
                break
            raise ValueError("bad token near: " + expr[pos:pos + 20])
        tokens.append(m.group(1))
        pos = m.end()
    if not tokens:
        return 0
    return P(tokens, macros).parse_or()


HEADER = """/* 本文件由 tools/split-fam.py 生成（%s）。
 *
 * 「一支一份」：条件编译已全部展开，族/链宏写死在下面。
 * 改这一支就直接改这个文件；不要再改 payload/src/cve-2026-98260-uid0.c
 * 指望它生效（该主源只用于重新生成 / 字面版对照）。
 * 重新生成会覆盖本文件里的手改内容，重构主源时请一并同步。
 */
#define EXTRACTKIT_FAMILY_ID "%s"
#define EXTRACTKIT_FAMILY_INT %d
#define EXTRACTKIT_CHAIN %d
#define EXTRACTKIT_NO_REAL_CRED %d
"""


def split(fam):
    fid, fs, num, chain, expect = FAMS[fam]
    macros = seed_macros(fs, num, chain, expect)
    # 让 #ifndef EXTRACTKIT_NO_REAL_CRED 的默认 0 落进 inactive 分支，
    # 否则展开后会多一条写死 0 的 #define，把 66.c 的 1 顶掉。
    macros["EXTRACTKIT_NO_REAL_CRED"] = str(NO_REAL_CRED.get(fam, 0))
    lines = SRC.read_text(encoding="utf-8").splitlines()
    out = []
    stack = []
    active = True
    dropped = 0
    for ln in lines:
        s = ln.lstrip()
        if s.startswith("#"):
            d = re.match(r"#\s*(if|ifdef|ifndef|elif|else|endif|define|undef)\b\s*(.*)$", s)
            if not d:
                if active:
                    out.append(ln)
                continue
            kw, rest = d.group(1), d.group(2).strip()
            if kw in ("if", "ifdef", "ifndef"):
                parent = active
                if not parent:
                    cond = False
                elif kw == "if":
                    cond = bool(eval_expr(rest, macros))
                else:
                    name = rest.split()[0]
                    cond = (name in macros) if kw == "ifdef" else (name not in macros)
                stack.append([parent, cond])
                active = parent and cond
            elif kw == "elif":
                e = stack[-1]
                if e[0] and not e[1]:
                    cond = bool(eval_expr(rest, macros))
                    e[1] = cond
                    active = cond
                else:
                    active = False
            elif kw == "else":
                e = stack[-1]
                cond = e[0] and not e[1]
                e[1] = True
                active = cond
            elif kw == "endif":
                active = stack.pop()[0]
            else:  # define / undef
                if active:
                    if kw == "undef":
                        macros.pop(rest.split()[0], None)
                    else:
                        m = re.match(r"([A-Za-z_]\w*)(\s+.*)?$", rest)
                        if m and "(" not in rest.split()[0]:
                            macros[m.group(1)] = (m.group(2) or " 1").strip()
                    out.append(ln)
                else:
                    dropped += 1
            continue
        if active:
            out.append(ln)
    if stack:
        sys.exit("[split] unterminated #if (depth %d)" % len(stack))

    head = HEADER % (fam, fs, num, chain, NO_REAL_CRED.get(fam, 0))
    if expect:
        head += '#define EXPECT_FAMILY "%s"\n' % expect
    dst = OUTDIR / (fid + ".c")
    dst.write_text(head + "\n" + chr(10).join(out) + chr(10),
                   encoding="utf-8", newline=chr(10))
    print("[split] %-7s -> %s  (%d 行, 丢弃 #define %d 条)" %
          (fam, dst.relative_to(ROOT).as_posix(), len(out) + head.count(chr(10)), dropped))
    return dst


def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    only = None
    if "--fam" in sys.argv:
        only = sys.argv[sys.argv.index("--fam") + 1]
    todo = [only] if only else list(FAMS)
    for fam in todo:
        if fam not in FAMS:
            sys.exit("unknown fam: " + fam)
        split(fam)
    probe = OUTDIR.parent / "_split_probe.c"
    if probe.exists():
        probe.unlink()


if __name__ == "__main__":
    main()
