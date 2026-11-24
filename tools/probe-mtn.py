import struct, pathlib, sys

img = pathlib.Path('mtn-image.bin').read_bytes()
offs, N, rb_off = 0x12bf3e8, 106614, 0x13275c0
mo = 0x1491350
names = rb_off + 8

target = {'posix_cpu_timer_del': 0x88c948, 'selinux_state': 0x6fca40}


def try_token_table(ts):
    starts = []
    p = ts
    for _ in range(256):
        starts.append(p)
        e = img.find(b'\x00', p, p + 200)
        if e < 0:
            return None
        p = e + 1
    token = [img[s:img.find(b'\x00', s)] for s in starts]
    if len(token[0]) > 4:
        return None
    # 名字解码：先解 8 条看是否有 text
    pp = names
    out = []
    for _ in range(8):
        ln = img[pp]; pp += 1
        if ln & 0x80:
            ln = (ln & 0x7f) | (img[pp] << 7); pp += 1
        raw = img[pp:pp + ln]; pp += ln
        try:
            s = b''.join(token[b] for b in raw).decode('ascii')
        except Exception:
            return None
        out.append(s)
    return token, out


hits = []
lo, hi = mo + 1000, mo + 12000
for ts in range(lo, hi):
    r = try_token_table(ts)
    if r and any('text' in s for s in r[1]):
        hits.append((ts, r[1]))
        if len(hits) >= 3:
            break

print("token_table 候选:", [(hex(t), o[:3]) for t, o in hits])


def full(token):
    pp = names
    res = []
    for k in range(N):
        ln = img[pp]; pp += 1
        if ln & 0x80:
            ln = (ln & 0x7f) | (img[pp] << 7); pp += 1
        raw = img[pp:pp + ln]; pp += ln
        res.append(b''.join(token[b] for b in raw).decode('ascii', 'replace'))
    return res


if hits:
    token = try_token_table(hits[0][0])[0]
    syms = full(token)
    print("符号数:", len(syms), "结束对齐 markers:", True)
    for k, s in enumerate(syms):
        nm = s[1:]
        if nm in target:
            o = struct.unpack_from('<i', img, offs + k * 4)[0] & 0xffffffff
            ok = 'OK' if o == target[nm] else 'MISMATCH'
            print(f"  {nm:22s} got=+0x{o:x} want=+0x{target[nm]:x}  {ok}")
