import hashlib, os, shutil, sys
SRC  = r"D:\deepseek work\_glpreload"
DST  = r"D:\deepseek work\extract-kit\app\src\main\assets\payload\ghost\cve-2026-98260-uid0-6.1-ghost"
WANT_SIZE = 6470288
WANT_SHA  = "c033080b4dae58d561742d0ad880d63176514f984a44ed1298a9bb2bcad650e5"

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()

if not os.path.isfile(SRC):
    sys.exit("source missing: " + SRC)
size = os.path.getsize(SRC)
if size != WANT_SIZE:
    sys.exit("source size %d != %d" % (size, WANT_SIZE))
s = sha(SRC)
if s != WANT_SHA:
    sys.exit("source sha256 %s != %s" % (s, WANT_SHA))
os.makedirs(os.path.dirname(DST), exist_ok=True)
tmp = DST + ".tmp"
shutil.copyfile(SRC, tmp)
if os.path.getsize(tmp) != WANT_SIZE or sha(tmp) != WANT_SHA:
    os.remove(tmp); sys.exit("copy verification failed")
os.replace(tmp, DST)
print("imported", DST)
print("size  ", os.path.getsize(DST))
print("sha256", sha(DST))
