#!/usr/bin/env python3
"""AUD-044 fun probe: the built-in table of published rounds against the vector files, read here
without xtask: every salt, key, container, setting and reading of the 27 vectors."""
import json,re
t=open('src/mhfe/published_rounds.rs').read()
blocks=t.split('PublishedVector {\n')[1:]
ok=0;bad=[]
for b in blocks:
    name=re.search(r'name: "([^"]+)"',b).group(1)
    folder='suite4' if name.startswith('same-length') else 'suite3'
    v=json.load(open(f'tests/spec/vectors/{folder}/{name}.json'))
    rounds=v['encryption']['rounds']
    salts=re.findall(r'salt: hex\("([0-9a-f]+)"\)',b); keys=re.findall(r'key: hex\("([0-9a-f]+)"\)',b)
    js=[r['salt_hex'] for r in rounds]; jk=[r['argon2_key_hex'] for r in rounds]
    c=re.search(r'container: "([^"]+)"',b).group(1)
    p=int(re.search(r'pim: (\d+)',b).group(1)); m=int(re.search(r'memory_level: (\d+)',b).group(1))
    same= js==salts and jk==keys and c==v['container'] and p==v['inputs']['pim'] and m==v['inputs']['memory_level'] and len(salts)==12
    ok+=same
    if not same: bad.append(name)
print(ok,'of',len(blocks),'vectors equal the files',bad[:3])
