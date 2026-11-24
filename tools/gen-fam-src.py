"""把新的单份 payload 源展开成六份互不引用的族源（payload/src/fam2/<id>.c）。

设计（用户 m21462 / m21484）：
- 只认上游 /refdata/ekit-gh 的 payload 思路（fake cred + ksu_stage late-load），
  旧的 honor/brm/k618 链全部淘汰。
- 六支各一份独立 .c：生成之后就只改那一支，改一支不会连带改其余五支。

用法：python tools/gen-fam-src.py
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = ROOT / "payload/src/cve-2026-98260-uid0.c"
OUT = ROOT / "payload/src/fam2"

# 版本前缀 -> 文件名（沿用 payload/src/fam 时代的编号习惯，方便对日志）
IDS = [("5.10", "510"), ("5.15", "515"), ("6.1", "61"),
       ("6.6", "66"), ("6.12", "612"), ("6.18", "618")]

HEAD = """/* payload/src/fam2/{fn}.c - CVE-2026-98260 uid0 payload, kernel family {fam}
 *
 * 本文件由 tools/gen-fam-src.py 从 payload/src/cve-2026-98260-uid0.c 生成，
 * 生成后就是这一支的**独立副本**：六支互不 include、互不 -D 覆盖，
 * 改 5.10 那份不会动 6.6 这份。
 */
__attribute__((used)) static const char EK_FAMILY_BANNER[] =
    "cve-2026-98260 fam {fam}";
"""


def main() -> int:
    if not BASE.is_file():
        sys.exit("missing base payload src: %s" % BASE)
    body = BASE.read_text(encoding="utf-8")
    OUT.mkdir(parents=True, exist_ok=True)
    for fam, fn in IDS:
        text = HEAD.format(fam=fam, fn=fn) + "\n" + body
        dst = OUT / (fn + ".c")
        dst.write_text(text, encoding="utf-8", newline="\n")
        print("[fam2] %s -> %s (%d B)" % (fam, dst.name, len(text.encode("utf-8"))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
