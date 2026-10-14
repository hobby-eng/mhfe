#!/usr/bin/env python3
"""AUD-024 verifier (commit b6fca69): which module edges tie the independent parts of the library
(CORE-04) to the encryption core, apart from the error.rs edges (the RUST-04 finding) and the
self-check code. Runs guide-lib-core/module_cycles.py, drops every edge into error, self_check and
validation_fixtures, every edge made in a known_answers file, and the edges of the front ends
(wasm_api) and of error, self_check and self_test, then reports which parts reach mhfe, feistel,
engine, wallet, rehearsal or container, and which of the six candidate edges are needed for that.
Exits 1 while a part reaches the core. Run from the repository root."""
import collections, itertools, pathlib, re, subprocess, sys

here = pathlib.Path(__file__).resolve().parent
log = subprocess.run([sys.executable, str(here.parent / 'guide-lib-core' / 'module_cycles.py')],
                     capture_output=True, text=True).stdout
edges, where = collections.defaultdict(set), {}
for a, b, loc in re.findall(r'^\s+(\w+) -> (\w+)\s+\((\S+)\)', log, re.M):
    if b in ('error', 'self_check', 'validation_fixtures') or a in ('self_check', 'wasm_api', 'validation_fixtures', 'error', 'self_test'):
        continue
    if 'known_answers' in loc:
        continue
    edges[a].add(b); where[(a, b)] = loc
CANDIDATE = {'phrase->container': {('phrase', 'container')},
             'container->mhfe/wallet/rehearsal': {('container', 'mhfe'), ('container', 'wallet'), ('container', 'rehearsal')},
             'memory->engine': {('memory', 'engine')}, 'packing->phrase': {('packing', 'phrase')},
             'suite->engine': {('suite', 'engine')}, 'engine->wasm_api': {('engine', 'wasm_api')}}
CORE = {'mhfe', 'feistel', 'engine', 'wallet', 'rehearsal', 'container'}
PARTS = ('repair', 'check_word', 'password', 'new_password', 'strength', 'word_hints', 'wallet_check',
         'word_wishes', 'phrase', 'memory', 'packing')

def reach(src, drop):
    seen, todo = set(), [src]
    while todo:
        v = todo.pop()
        for w in edges[v]:
            if (v, w) not in drop and w not in seen:
                seen.add(w); todo.append(w)
    return seen

tied = [p for p in PARTS if reach(p, set()) & CORE]
for p in tied:
    print(f'{p} reaches the core: {sorted(reach(p, set()) & CORE)}')
for name, drop in CANDIDATE.items():
    present = [f'{a}->{b} ({where[(a, b)]})' for a, b in sorted(drop) if (a, b) in where]
    print(f'edge {name}: {", ".join(present) or "absent"}')
smallest = None
for k in range(1, len(CANDIDATE) + 1):
    for combo in itertools.combinations(CANDIDATE, k):
        drop = set().union(*(CANDIDATE[c] for c in combo))
        if not any(reach(p, drop) & CORE for p in PARTS):
            smallest = combo
            break
    if smallest:
        break
print('smallest set of candidate edges whose removal frees every part:', smallest)
print(f'{len(tied)} part(s) reach the encryption core')
sys.exit(1 if tied else 0)
