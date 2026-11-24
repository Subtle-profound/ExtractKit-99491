#!/usr/bin/env python3
"""gen-module-syms.py - build our own kernel symbol table for a kernel module.

Reads a kallsyms dump (produced by tools/find-kallsyms.py) plus a .ko, resolves
every SHN_UNDEF symbol the module needs, and prints a Kotlin blob usable by
ModuleSyms.kt.  Nothing external is bundled: the table is generated from the
boot.img of the same build.

usage: python tools/gen-module-syms.py KALLSYMS.txt MODULE.ko --release <rel>
       [--kotlin FILE] [--map FILE]
"""
import argparse, struct, sys

# Only alias-safe renames: same function, same signature.  Anything whose
# semantics differ (e.g. kmem_cache_alloc_trace vs __kmalloc) is NOT guessed --
# patching a wrong address would be worse than refusing to load.
FALLBACK = {
    "printk": ["_printk"],
    "__list_del_entry_valid": ["__list_del_entry_valid_or_report"],
    "__list_add_valid": ["__list_add_valid_or_report"],
    "find_next_bit": ["_find_next_bit"],
}


def load_syms(path):
    syms = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.split()
            if len(p) < 2:
                continue
            name = p[-1]
            if name not in syms:
                syms[name] = int(p[0], 16)
    return syms


def ko_undef(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF" or d[4] != 2:
        raise SystemExit("not an ELF64 file: " + path)
    shoff = struct.unpack_from("<Q", d, 40)[0]
    shnum = struct.unpack_from("<H", d, 60)[0]
    symo = nsym = stro = 0
    for i in range(shnum):
        o = shoff + i * 64
        if struct.unpack_from("<I", d, o + 4)[0] == 2:
            symo = struct.unpack_from("<Q", d, o + 24)[0]
            nsym = struct.unpack_from("<Q", d, o + 32)[0] // 24
            link = struct.unpack_from("<I", d, o + 40)[0]
            stro = struct.unpack_from("<Q", d, shoff + link * 64 + 24)[0]
    out = []
    for i in range(1, nsym):
        o = symo + i * 24
        if struct.unpack_from("<H", d, o + 6)[0] != 0:
            continue
        n = struct.unpack_from("<I", d, o)[0]
        e = d.index(0, stro + n)
        out.append(d[stro + n:e].decode("latin1"))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kallsyms")
    ap.add_argument("module")
    ap.add_argument("--release", default="")
    ap.add_argument("--kotlin", default="")
    ap.add_argument("--map", default="")
    ap.add_argument("--all", action="store_true",
                    help="emit every import, 0x0 for the ones we cannot resolve")
    a = ap.parse_args()

    syms = load_syms(a.kallsyms)
    names = ko_undef(a.module)
    rows, fallback, missing = [], [], []
    for n in names:
        if n in syms:
            rows.append((n, syms[n]))
            continue
        hit = None
        for alt in FALLBACK.get(n, []):
            if alt in syms:
                hit = (alt, syms[alt])
                break
        if hit:
            fallback.append((n, hit[0]))
            rows.append((n, hit[1]))
        else:
            missing.append(n)

    print("# module %s undef=%d resolved=%d fallback=%d missing=%d"
          % (a.module, len(names), len(rows), len(fallback), len(missing)),
          file=sys.stderr)
    for n, alt in fallback:
        print("#   fallback %s -> %s" % (n, alt), file=sys.stderr)
    for n in missing:
        print("#   MISSING %s" % n, file=sys.stderr)

    if a.map:
        with open(a.map, "w", encoding="utf-8", newline="\n") as f:
            f.write("# extractkit-map v1\n# kernel=%s\n# nsyms=%d\n"
                    % (a.release, len(rows)))
            for n, v in rows:
                f.write("%s 0x%x\n" % (n, v))
    if a.kotlin:
        if a.all:
            got = dict(rows)
            body = "\\n".join("%s 0x%x" % (n, got.get(n, 0)) for n in names)
        else:
            body = "\\n".join("%s 0x%x" % (n, v) for n, v in rows)
        with open(a.kotlin, "w", encoding="utf-8", newline="\n") as f:
            f.write(body + "\n")


if __name__ == "__main__":
    main()
