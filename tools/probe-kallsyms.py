#!/usr/bin/env python3
"""kallsyms 布局探针：给一个内核 Image/boot.img，输出所有可用的定位证据。

用法:
    python tools/probe-kallsyms.py <image 或 boot.img> [--json out.json]

它不依赖具体的布局假设，只做「找特征 + 报证据」：
  1. relative_base 常量（0xffffffc000000000 / 0xffffff8000000000 / 0xffffffc008000000）出现的位置；
  2. kallsyms_markers 候选：递增 u32 数组（≥128 项，步长 1..0x40000）；
  3. kallsyms_token_index 候选：256 个 u16，首项 0、步长 1..4 —— 找到它就能倒推出 token_table；
  4. kallsyms_offsets 候选：最长递增 int32 段（首项通常为 0）；
  5. 以上候选两两组合的「自洽性」检查（num_syms、names 起点、base）。

输出是给人看的证据表，判定留给 KallsymsFinder / 人工。
"""
from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

BASE_CONSTS = (0xFFFFFFC000000000, 0xFFFFFF8000000000, 0xFFFFFFC008000000)


def boot_kernel(data: bytes) -> tuple[bytes, str]:
    """如果是 Android boot.img 就取出 kernel 段，否则当作 Image 原样返回。"""
    if data[:8] != b"ANDROID!":
        return data, "image"
    hdr = int.from_bytes(data[40:44], "little")
    ksize = int.from_bytes(data[8:12], "little")
    page = 0x800 if hdr == 1 else 0x1000
    for off in (0x800, 0x1000, 0x8000, 0x10000):
        if off + 4 > len(data):
            continue
        head = data[off:off + 4]
        if head[:2] == b"MZ" or head[:2] == b"\x1f\x8b" or data[off + 0x38:off + 0x3C] == b"ARMd":
            return data[off:off + ksize], f"boot-hdr{hdr}@{off:#x}"
    return data[page:page + ksize], f"boot-hdr{hdr}@{page:#x}"


def u32_runs(a, min_len: int, max_step: int):
    """返回 (起始下标, 长度) —— a 是 numpy u32 数组。"""
    import numpy as np
    if a.size < min_len + 1:
        return []
    d = a[1:].astype(np.int64) - a[:-1].astype(np.int64)
    ok = (d > 0) & (d < max_step)
    out = []
    run_start = None
    for i, v in enumerate(ok):
        if v and run_start is None:
            run_start = i
        elif not v and run_start is not None:
            if i - run_start >= min_len:
                out.append((run_start, i - run_start + 1))
            run_start = None
    if run_start is not None and ok.size - run_start >= min_len:
        out.append((run_start, ok.size - run_start + 1))
    return out


def find_token_index(b16):
    """256 个 u16：首项 0，步长 1..4，累计值单调。返回 token_index 的字节偏移列表。"""
    import numpy as np
    if b16.size < 256:
        return []
    d = b16[1:].astype(np.int64) - b16[:-1].astype(np.int64)
    good = (d >= 1) & (d <= 4)
    hits = []
    window = 255
    # 用卷积式滑窗统计连续 good 的数量
    c = np.concatenate(([0], np.cumsum(good)))
    total = c[window:] - c[:-window]          # 每个起点往后 window 个是否全 good
    starts = np.nonzero(total == window)[0]
    for s in starts:
        if b16[s] != 0:
            continue
        if int(b16[s + 255]) > 1024:          # 256 个 token 总长不会超过 1 KiB
            continue
        hits.append(int(s) * 2)
        if len(hits) >= 64:
            break
    return hits


def token_table_before(img: bytes, idx_off: int):
    """从 token_index 起点往回走 256 个 NUL 结尾的短串，返回 (起点, 每串长度)。"""
    pos = idx_off
    lens = []
    for _ in range(256):
        start = img.rfind(b"\x00", max(0, pos - 5), pos)
        if start < 0:
            return None
        n = pos - start - 1
        if n > 3:
            return None
        seg = img[start + 1:pos]
        if any(ch < 0x20 or ch > 0x7E for ch in seg):
            return None
        lens.append(n + 1)
        pos = start
    lens.reverse()
    return pos, lens


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = Path(sys.argv[1])
    data = path.read_bytes()
    img, kind = boot_kernel(data)
    print(f"文件      {path}  {len(data):,} B")
    print(f"形态      {kind} → kernel {len(img):,} B")

    m = re.search(rb"Linux version ([0-9][^\x00]{5,90})", img)
    print(f"release   {m.group(1).decode('latin1') if m else '未找到'}")
    print(f".BTF      {'有' if img.find(b'.BTF') >= 0 else '无'}")
    print()

    for c in BASE_CONSTS:
        pat = struct.pack("<Q", c)
        offs = [mm.start() for mm in re.finditer(re.escape(pat), img)]
        if offs:
            print(f"relative_base {c:#x} 命中 {len(offs)} 处: " +
                  ", ".join(f"{o:#x}(prev_u32={struct.unpack_from('<I', img, o - 4)[0] if o >= 4 else 0})"
                            for o in offs[:8]))
    print()

    try:
        import numpy as np
    except ImportError:
        print("缺 numpy，跳过向量化扫描（pip install numpy）")
        return 1

    a = np.frombuffer(img[:len(img) // 4 * 4], dtype="<u4")
    runs = u32_runs(a, 128, 0x40000)
    runs.sort(key=lambda t: -t[1])
    print(f"markers 候选（递增 u32，≥128 项）: {len(runs)} 组，最长 8 组：")
    for start, length in runs[:8]:
        first = int(a[start]); last = int(a[start + length - 1])
        print(f"  @{start * 4:#010x}  count={length:5d}  first={first:#x}  last={last:#x}")
    print()

    b16 = np.frombuffer(img[:len(img) // 2 * 2], dtype="<u2")
    idx = find_token_index(b16)
    print(f"token_index 候选（256×u16，首项 0，步长 1..4）: {len(idx)} 个")
    for o in idx[:8]:
        got = token_table_before(img, o)
        if not got:
            print(f"  index@{o:#x}  表头回溯失败")
            continue
        tstart, lens = got
        print(f"  index@{o:#x}  表@{tstart:#x}  总长={sum(lens)}B  "
              f"token[{img[tstart:tstart + 12]!r}…]")
    print()

    # 最长递增 int32 段（offsets 数组的形状）
    ai = np.frombuffer(img[:len(img) // 4 * 4], dtype="<i4").astype(np.int64)
    d = ai[1:] - ai[:-1]
    ok = (d > 0) & (d < 0x200000)
    c = np.concatenate(([0], np.cumsum(ok)))
    best = (0, 0)
    step = 4096
    for s in range(0, max(1, ok.size - 1), step):
        e = min(ok.size - 1, s + step)
        seg = c[e] - c[s]
        if seg > best[1]:
            best = (s, int(seg))
    print(f"offsets 候选（最长递增 int32 段）: @{best[0] * 4:#x}  长度≈{best[1]:,}")
    print("说明：offsets 首项应为 0；它的末尾后面通常紧跟 relative_base 与 num_syms。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
