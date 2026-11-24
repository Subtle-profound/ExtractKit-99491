"""重新生成 assets/payload/SHA256SUMS.txt（历史位置那份）。

assets/SHA256SUMS.txt 是权威清单（测试 PayloadCatalogTest 读它），由
build_payload.py / build_fam.py 各自追加；assets/payload/SHA256SUMS.txt
是早期位置，两边长期漂移（9.192 时 5.10/5.15/6.1/6.12/6.18 五行全是旧哈希）。
这里按磁盘上的真实字节重写一遍，避免「同一份清单两个版本」。
"""
import hashlib
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
ASSETS = ROOT / "app/src/main/assets"
OUT = ASSETS / "payload/SHA256SUMS.txt"

rows = []
for p in sorted((ASSETS / "payload").rglob("*")):
    if not p.is_file() or p.name == "SHA256SUMS.txt" or p.name == "index.txt":
        continue
    rel = p.relative_to(ASSETS).as_posix()
    rows.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}")
OUT.write_text(chr(10).join(rows) + chr(10), encoding="utf-8", newline=chr(10))
print(f"[sums] {OUT.as_posix()} {len(rows)} rows")
for r in rows:
    print("  " + r)
