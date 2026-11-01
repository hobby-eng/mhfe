# AUD-044 fun probe: public or crate functions of the reviewed files that nothing but tests uses.
import re,subprocess,glob,sys
files="mhfe rekey repair rehearsal search operation detection container check_word wallet wallet_check phrase password new_password packing suite eff self_check self_test word_hints word_wishes validation_fixtures".split()
idx={}
for line in open('../tmp/aud044/index.tsv'):
    p=line.rstrip('\n').split('\t')
    if len(p)==3 and p[2].isdigit(): idx[p[0]]=int(p[2])
def code(path):
    t=open(path,errors='replace').read().split('\n')
    n=idx.get(path,0)
    if n: t=t[:n-1]
    return '\n'.join(l for l in t if not l.lstrip().startswith('//'))
allrs=[p for p in glob.glob('src/**/*.rs',recursive=True)+glob.glob('xtask/src/**/*.rs',recursive=True)]
known=[p for p in allrs if 'known_answers' in p]
corpus={p:code(p) for p in allrs}
web=''
for p in glob.glob('web/*.js')+glob.glob('web/*.ts'): web+=open(p,errors='replace').read()
defs=[]
for f in files+['self_check/sets']:
    p=f'src/{f}.rs'
    for m in re.finditer(r'^\s*pub(?:\(crate\))? (?:const )?fn (\w+)',corpus[p],re.M):
        defs.append((p,m.group(1)))
for p,name in sorted(set(defs)):
    users=[q for q,t in corpus.items() if re.search(r'\b'+name+r'\b',t) and not (q==p and len(re.findall(r'\b'+name+r'\b',t))==1)]
    nonka=[q for q in users if 'known_answers' not in q]
    if not nonka: print('ONLY known_answers' if users else 'UNUSED', p, name, users[:2])
