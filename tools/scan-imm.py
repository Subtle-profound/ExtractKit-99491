import pathlib, struct, sys, re

def scan(path):
    d = pathlib.Path(path).read_bytes()
    # 找 .text 范围（简易：用 ELF program headers）
    e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', d, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', d, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', d, 0x3e)[0]
    strtab_off = struct.unpack_from('<Q', d, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
    text = None
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        name_off = struct.unpack_from('<I', d, base)[0]
        name = d[strtab_off + name_off: d.find(b'\0', strtab_off + name_off)].decode()
        off = struct.unpack_from('<Q', d, base + 0x18)[0]
        size = struct.unpack_from('<Q', d, base + 0x20)[0]
        if name == '.text':
            text = (off, size)
    if text is None:
        print("no .text")
        return
    off, size = text
    print(f"{path}: .text @0x{off:x} size=0x{size:x}")

    def mov_const(insn):
        # MOVZ / MOVK
        if (insn & 0x7F800000) == 0x52800000:      # MOVZ 32/64
            hw = (insn >> 21) & 3
            imm = (insn >> 5) & 0xFFFF
            rd = insn & 0x1F
            return ('movz', hw, imm, rd)
        if (insn & 0x7F800000) == 0x72800000:      # MOVK
            hw = (insn >> 21) & 3
            imm = (insn >> 5) & 0xFFFF
            rd = insn & 0x1F
            return ('movk', hw, imm, rd)
        return None

    found = {}
    for i in range(0, size - 4 * 12, 4):
        insn = struct.unpack_from('<I', d, off + i)[0]
        m = mov_const(insn)
        if not m or m[0] != 'movz':
            continue
        kind, hw, imm, rd = m
        val = imm << (16 * hw)
        ok = True
        for j in range(1, 10):
            nxt = struct.unpack_from('<I', d, off + i + 4 * j)[0]
            n2 = mov_const(nxt)
            if not n2:
                break
            k2, hw2, imm2, rd2 = n2
            if rd2 != rd:
                break
            if k2 == 'movk':
                val = (val & ~(0xFFFF << (16 * hw2))) | (imm2 << (16 * hw2))
        if 0xffffffc080000000 <= val <= 0xffffffc090000000:
            found.setdefault(val, []).append(off + i)
    for val in sorted(found):
        print(f"   0x{val:x}   (x{len(found[val])})  @0x{found[val][0]:x}")
    return found

for p in sys.argv[1:]:
    scan(p)
