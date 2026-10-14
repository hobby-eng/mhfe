#!/usr/bin/env python3
"""AUD-024 guide-lib-core: the dependency graph of the library's top-level modules (non-test code),
from `crate::<module>` paths and crate-root re-exports, and the cycles among them (CHECK-ARC-001).
Prints every strongly connected component of more than one module with its edges and the line
that makes each edge. Exits 1 when there is such a cycle. Run from the repository root."""
import re, pathlib, collections

lib = pathlib.Path('src/lib.rs').read_text()
modules = re.findall(r'^\s*(?:pub\s+)?mod\s+([a-z_0-9]+);', lib, re.M)
# Root re-exports: name -> module
reexport = {}
for module, names in re.findall(r'pub use ([a-z_0-9]+)::\{([^}]*)\}', lib, re.S):
    for name in re.split(r'[\s,]+', names):
        if name:
            reexport[name] = module
for module, name in re.findall(r'pub use ([a-z_0-9]+)::([A-Za-z_0-9]+);', lib):
    reexport[name] = module

def files_of(module):
    files = [pathlib.Path(f'src/{module}.rs')]
    folder = pathlib.Path(f'src/{module}')
    if folder.is_dir():
        files += sorted(folder.rglob('*.rs'))
    return [f for f in files if f.exists() and 'published_rounds' not in f.name]

def strip_tests(text):
    out, skip, depth = [], False, 0
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not skip and re.match(r'\s*#\[cfg\((all\()?test', line) and i + 1 < len(lines) and re.search(r'\bmod\s+tests\b', lines[i + 1]):
            skip, depth = True, 0
            continue
        if skip:
            depth += line.count('{') - line.count('}')
            if depth <= 0 and '}' in line:
                skip = False
            continue
        out.append(line)
    return '\n'.join(out)

edges = collections.defaultdict(set)
evidence = {}
for module in modules:
    for path in files_of(module):
        text = strip_tests(path.read_text())
        if path.name == 'test_support.rs':
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if line.strip().startswith('//'):
                continue
            for target in re.findall(r'crate::([a-z_0-9]+)', line):
                if target in modules and target != module:
                    edges[module].add(target); evidence.setdefault((module, target), f'{path}:{number}')
            for group in re.findall(r'use crate::\{([^}]*)\}', line):
                for name in re.split(r'[\s,]+', group):
                    if name in reexport and reexport[name] != module:
                        edges[module].add(reexport[name]); evidence.setdefault((module, reexport[name]), f'{path}:{number}')
            for name in re.findall(r'crate::([A-Z][A-Za-z_0-9]*|[a-z_0-9]+)\b', line):
                if name in reexport and reexport[name] != module:
                    edges[module].add(reexport[name]); evidence.setdefault((module, reexport[name]), f'{path}:{number}')

# Tarjan
index, low, stack, on, sccs, counter = {}, {}, [], set(), [], [0]
def visit(v):
    index[v] = low[v] = counter[0]; counter[0] += 1; stack.append(v); on.add(v)
    for w in edges[v]:
        if w not in index:
            visit(w); low[v] = min(low[v], low[w])
        elif w in on:
            low[v] = min(low[v], index[w])
    if low[v] == index[v]:
        comp = []
        while True:
            w = stack.pop(); on.discard(w); comp.append(w)
            if w == v: break
        sccs.append(comp)
import sys
sys.setrecursionlimit(10000)
for v in modules:
    if v not in index:
        visit(v)
cycles = [comp for comp in sccs if len(comp) > 1]
for comp in cycles:
    if True:
        print('cycle among:', ', '.join(sorted(comp)))
        for a in sorted(comp):
            for b in sorted(edges[a]):
                if b in comp:
                    print(f'  {a} -> {b}  ({evidence[(a, b)]})')
print(f'{len(cycles)} cycle(s) of modules')
sys.exit(1 if cycles else 0)
