"""AUD-010 cli-terminal probe: the use-graph of the library's top-level modules (CHECK-ARC-001).

    python3 docs/audits/AUD-010-harnesses/cli-terminal/module-graph.py [repository root]

Resolves every `crate::` path of the library's source files (src/, without src/bin) to the
top-level module it names: `crate::repair::x` to `repair`, and a name that src/lib.rs re-exports,
such as `crate::MhfeError`, to the module it comes from (`error`). Grouped imports
(`use crate::{a, b::c}`) are expanded. A `#[cfg(test)] mod tests` at the end of a file is left
out, as only tests use it. `super::` paths are not followed (they stay within one top-level module,
or reach the crate root only from tests). Limits: a path built by a macro, or a `crate::` path
inside a test module that is not the last item of its file, is read as written.

Two views are printed:
1. every file under its top-level module;
2. the self-check wiring apart: each module's `known_answers.rs` and `self_check/sets.rs` as nodes
   of their own, so that the modules' own code is seen without the known answers that every
   self-check set gathers.
For each view it prints the edges and every strongly connected component of more than one module.

Checks (exit 1 when one fails, 0 otherwise):
- in view 2, none of the parts that the browser package offers as independent modules besides the
  core (repair, check_word, new_password, wallet_check, strength) is in a cycle with another
  module: another program could not take it without the modules of that cycle;
- no library file includes a file of the binary (`#[path]`).
Reads files only.
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[4])
SRC = ROOT / "src"
# The parts of MhfeRepair, MhfePasswords and MhfeWallet (docs/BROWSER-PACKAGE.md), which AGENTS.md
# asks to be independent modules that another program can take without the rest.
INDEPENDENT = {"repair", "check_word", "new_password", "wallet_check", "strength"}


def node_of(path: Path, split_self_checks: bool) -> str:
    relative = path.relative_to(SRC)
    if len(relative.parts) == 1:
        return relative.stem
    if split_self_checks and relative.name in ("known_answers.rs", "sets.rs"):
        return f"{relative.parts[0]}::{relative.stem}"
    return relative.parts[0]


def without_tests(text: str) -> str:
    match = re.search(r"^#\[cfg\(test\)\]\s*\n\s*mod tests\b", text, re.MULTILINE)
    return text[: match.start()] if match else text


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def expand_group(prefix: str, body: str) -> list:
    """Expands `a, b::c, d::{e, f}` below `prefix` into full paths."""
    paths, depth, current = [], 0, ""
    for character in body + ",":
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        if character == "," and depth == 0:
            item = current.strip()
            current = ""
            if not item:
                continue
            nested = re.match(r"^([\w:]*?)::\{(.*)\}$", item, re.DOTALL)
            if nested:
                paths += expand_group(prefix + nested.group(1) + "::", nested.group(2))
            else:
                paths.append(prefix + item)
            continue
        current += character
    return paths


def crate_names(text: str) -> list:
    """The first segment of every `crate::` path."""
    paths = []
    for match in re.finditer(r"crate::\{(.*?)\};", text, re.DOTALL):
        paths += expand_group("", match.group(1))
    for match in re.finditer(r"crate::(\w+)", text):
        paths.append(match.group(1))
    return [path.split("::")[0].split(" as ")[0].strip() for path in paths]


def root_reexports() -> dict:
    lib = strip_comments((SRC / "lib.rs").read_text(encoding="utf-8"))
    names = {}
    for match in re.finditer(r"pub use (\w+)::(\{.*?\}|\w+);", lib, re.DOTALL):
        module, items = match.group(1), match.group(2).strip("{}")
        for item in items.split(","):
            item = item.strip()
            if item:
                names[item.split(" as ")[-1].strip()] = module
    return names


def library_modules() -> set:
    lib = strip_comments((SRC / "lib.rs").read_text(encoding="utf-8"))
    return set(re.findall(r"^\s*(?:pub )?mod (\w+);", lib, re.MULTILINE))


def library_files() -> list:
    return [
        path
        for path in sorted(SRC.rglob("*.rs"))
        if path.relative_to(SRC).parts[0] != "bin" and path.name != "lib.rs"
    ]


def build_graph(split_self_checks: bool):
    known, reexports = library_modules(), root_reexports()
    graph, unresolved = defaultdict(set), set()
    for path in library_files():
        source = node_of(path, split_self_checks)
        graph[source]
        text = strip_comments(without_tests(path.read_text(encoding="utf-8")))
        for name in crate_names(text):
            target = name if name in known else reexports.get(name)
            if target is None:
                unresolved.add((source, name))
            elif target != source:
                graph[source].add(target)
    for node in list(graph):
        for target in list(graph[node]):
            graph[target]
    return graph, unresolved


def tarjan(graph: dict) -> list:
    index, low, stack, on_stack, result, counter = {}, {}, [], set(), [], [0]

    def visit(node):
        index[node] = low[node] = counter[0]
        counter[0] += 1
        stack.append(node)
        on_stack.add(node)
        for successor in sorted(graph[node]):
            if successor not in index:
                visit(successor)
                low[node] = min(low[node], low[successor])
            elif successor in on_stack:
                low[node] = min(low[node], index[successor])
        if low[node] == index[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == node:
                    break
            result.append(sorted(component))

    for node in sorted(graph):
        if node not in index:
            visit(node)
    return result


def show(title: str, graph: dict, unresolved: set) -> list:
    print(f"== {title}")
    print("edges (module -> modules it uses):")
    for node in sorted(graph):
        print(f"  {node} -> {', '.join(sorted(graph[node])) or '-'}")
    for source, name in sorted(unresolved):
        print(f"  unresolved: {source}: crate::{name}")
    components = [component for component in tarjan(graph) if len(component) > 1]
    print("cycles (strongly connected components of more than one module):")
    for component in components:
        print(f"  {', '.join(component)}")
    if not components:
        print("  none")
    return components


def main() -> int:
    sys.setrecursionlimit(10000)
    failures = []
    whole, unresolved = build_graph(split_self_checks=False)
    show("view 1: every file under its top-level module", whole, unresolved)
    split, unresolved = build_graph(split_self_checks=True)
    for component in show("view 2: known answers and self_check::sets apart", split, unresolved):
        caught = INDEPENDENT.intersection(component)
        if caught:
            failures.append(f"independent part(s) {sorted(caught)} in a cycle: {component}")
    for path in library_files():
        if "#[path" in path.read_text(encoding="utf-8"):
            failures.append(f"{path.relative_to(ROOT)} includes another file by #[path]")
    for failure in failures:
        print(f"FAIL: {failure}")
    print("module-graph: " + ("FAILED" if failures else "passed"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
