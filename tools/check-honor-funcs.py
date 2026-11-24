import re,os
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FUNCS=os.path.join(ROOT,'..','rev5x','funcs.txt')
C=os.path.join(ROOT,'payload','src','chain_honor.c')
ref=set()
for ln in open(FUNCS,encoding='utf-8',errors='replace'):
    m=re.match(r'^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+\S+\s+\S+\s+\d+\s+(\S+)',ln)
    if m: ref.add(m.group(3))
src=open(C,encoding='utf-8',errors='replace').read()
defs=re.findall(r'^static\s+[A-Za-z_][\w \*]*?\b([a-z_][a-z0-9_]*)\s*\(',src,re.M)
names=sorted(set(defs))
ours=[];matched=[]
for n in names:
    (matched if n in ref else ours).append(n)
print('static funcs:',len(names),'in ref funcs.txt:',len(matched),'not-in-ref:',len(ours))
for n in ours: print('  OURS:',n)
