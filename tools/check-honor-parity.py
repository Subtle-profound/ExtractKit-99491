import re,os
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN=os.path.join(ROOT,'..','rev5x','bin','libsysopt.so')
C=os.path.join(ROOT,'payload','src','chain_honor.c')
ALLOW=os.path.join(ROOT,'tools','honor-parity-allow.txt')
blob=open(BIN,'rb').read()
src=open(C,encoding='utf-8',errors='replace').read()
allow=set()
for ln in open(ALLOW,encoding='utf-8'):
    ln=ln.rstrip('\n')
    if ln and not ln.startswith('#'): allow.add(ln)
pats=re.findall(r'(?:logf|printf|puts|fprintf|flog)\(\s*"([^"]*)"',src)
ok=0;missing=[];used=set()
for p in sorted(set(pats)):
    probe=p.replace('\\n','').replace('\\t','').rstrip()
    if probe and probe.encode() in blob: ok+=1; continue
    if probe in allow: used.add(probe); continue
    missing.append(p)
print('format strings:',len(set(pats)),'in-reference:',ok,'allowlisted:',len(used),'missing:',len(missing))
for m in missing: print('  MISSING:',m)
for a in sorted(allow-used): print('  STALE-ALLOW:',a)
raise SystemExit(1 if missing else 0)
