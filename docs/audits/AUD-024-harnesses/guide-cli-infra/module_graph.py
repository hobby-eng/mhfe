"""Module dependency graph of the mhfe command-line binary (src/bin/mhfe), from `crate::<module>`
references and `use crate::{...}` lists in non-test code, with the strongly connected components
(cycles) among the top-level modules."""
import os, re, sys
root = sys.argv[1]
mods = {}
for dirpath, _, files in os.walk(root):
    for f in files:
        if f.endswith(".rs"):
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, root)
            top = rel.split(os.sep)[0].removesuffix(".rs")
            text = open(p, encoding="utf-8").read()
            text = text.split("#[cfg(test)]\nmod tests")[0]
            mods.setdefault(top, set())
            for m in re.finditer(r"crate::(\w+)", text):
                mods[top].add(m.group(1))
            for m in re.finditer(r"use crate::\{([^}]*)\}", text, re.S):
                for name in re.findall(r"(?:^|,)\s*(\w+)", m.group(1)):
                    mods[top].add(name)
            if top != "main":
                # `super::` from a submodule refers to its parent, which is the same top module.
                pass
names = set(mods)
graph = {m: sorted(d & names - {m}) for m, d in mods.items()}
# Tarjan
index = {}; low = {}; stack = []; on = set(); out = []; counter = [0]
def strong(v):
    index[v] = low[v] = counter[0]; counter[0] += 1; stack.append(v); on.add(v)
    for w in graph[v]:
        if w not in index:
            strong(w); low[v] = min(low[v], low[w])
        elif w in on:
            low[v] = min(low[v], index[w])
    if low[v] == index[v]:
        comp = []
        while True:
            w = stack.pop(); on.discard(w); comp.append(w)
            if w == v: break
        out.append(sorted(comp))
sys.setrecursionlimit(10000)
for v in sorted(graph):
    if v not in index: strong(v)
infra = {"main","menu","startup","style","terminal","hidden_input","typed_line","choice","flow","exit","protect","serve","system_random","time_text","readme","settings","test_tools","length_choice"}
for m in sorted(infra & names):
    print(f"{m} -> {', '.join(graph[m])}")
print()
for comp in out:
    if len(comp) > 1:
        print(f"cycle of {len(comp)}: {', '.join(comp)}")
