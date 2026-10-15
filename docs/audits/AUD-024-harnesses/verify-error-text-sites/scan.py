#!/usr/bin/env python3
"""AUD-024 (commit b6fca69): is MhfeError's Display the one place its messages are written?

Run from the mhfe repository root: python3 docs/audits/AUD-024-harnesses/verify-error-text-sites/scan.py

Checks, each printed with the places that break it:
  1. No Display arm of src/error.rs writes nothing but a caller's text (`write!(f, "{x}")`).
  2. No non-test code outside src/error.rs builds an MhfeError variant that carries free text
     (a String), with the text written at that place. Test code is left out: `#[cfg(test)]`
     modules and items, and files declared as `#[cfg(test)] mod x;`. Match patterns
     (`X(_)`, `X(name) =>`, `| X(..)`, `matches!`) are not counted.
  3. No browser binding writes the text of a library error code itself (a `{code}:` message
     built outside js_error).
Exit status: 0 when every check holds, 1 when any check fails.
"""
import collections
import pathlib
import re
import subprocess
import sys

FREE = ["InvalidPhrase", "InvalidContainer", "InvalidRepairWords", "InvalidWordWish",
        "InvalidAddress", "InvalidDerivationPath", "InvalidFingerprint", "Argon2",
        "InvalidRequest", "InvalidPasswordSize", "RandomFailed", "InvalidCoin", "Internal",
        "SelfCheckFailed"]


# `#[cfg(test)]` or `#[cfg(all(test, ...))]`, but not `not(test)`.
TEST_CFG = re.compile(r"#\[cfg\((test\)|all\((?:[^()]|\([^()]*\))*?(?<!not\()\btest\b)")


def item_end(lines, start):
    depth, started, m = 0, False, start
    while m < len(lines):
        depth += lines[m].count("{") - lines[m].count("}")
        if "{" in lines[m]:
            started = True
        if (started and depth <= 0) or (not started and lines[m].rstrip().endswith(";")):
            return m
        m += 1
    return len(lines) - 1


def non_test_lines(text):
    lines = text.split("\n")
    keep = [True] * len(lines)
    k = 0
    while k < len(lines):
        if TEST_CFG.match(lines[k].strip()):
            j = k + 1
            while j < len(lines) and lines[j].strip().startswith("#["):
                j += 1
            end = item_end(lines, j)
            for x in range(k, end + 1):
                keep[x] = False
            k = end + 1
            continue
        k += 1
    return [(i + 1, l) for i, l in enumerate(lines) if keep[i]]


def test_only_files(root):
    found = set()
    for p in root.rglob("*.rs"):
        for m in re.finditer(r"#\[cfg\((?:test|all\([^\]]*?\btest\b[^\]]*)\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\(crate\))?\s+)?mod\s+(\w+)\s*;", p.read_text()):
            base = p.parent if p.name in ("lib.rs", "main.rs") else p.with_suffix("")
            found.add(str(base / f"{m.group(1)}.rs"))
    return found


def main():
    root = pathlib.Path("src")
    if (root / "error_code.rs").is_file():
        # The remediated model has independently owned errors. Check their
        # payload types, including renamed variants, rather than exempting
        # old variant names whose payloads are now typed nested causes.
        gate = "scripts/verify-error-contracts.mjs"
        for arguments in (["--self-test"], []):
            result = subprocess.run(["node", gate, *arguments], check=False)
            if result.returncode:
                return result.returncode
        print("result: PASS (module-owned typed errors and binding messages)")
        return 0
    failed = False

    # 1. Display arms that write only the caller's text.
    error_rs = (root / "error.rs").read_text().split("\n")
    only_payload = [(i + 1, l.strip()) for i, l in enumerate(error_rs)
                    if re.search(r'=>\s*write!\(f,\s*"\{\w+\}"\)', l)]
    print("== 1. Display arms that write only the caller's text")
    for ln, l in only_payload:
        print(f"src/error.rs:{ln}: {l}")
    print(f"count: {len(only_payload)}")
    failed |= bool(only_payload)

    # 2. Construction sites of free-text variants.
    skip = test_only_files(root)
    name = re.compile(r"(?<![:\w])(?:crate::)?(?:MhfeError|Self)::(" + "|".join(FREE) + r")\b")
    sites, by_variant, by_file = [], collections.Counter(), collections.Counter()
    for p in sorted(root.rglob("*.rs")):
        sp = str(p)
        if sp in skip or sp == "src/error.rs":
            continue
        for ln, line in non_test_lines(p.read_text()):
            s = line.strip()
            if s.startswith("//"):
                continue
            for m in name.finditer(line):
                before, after = line[:m.start()], line[m.end():]
                if re.match(r"\s*(\(\s*(_|\.\.)\s*\)|\{\s*\.\.\s*\})", after):
                    continue  # a pattern X(_) / X { .. }
                if re.match(r"\s*\(\s*\w+\s*\)\)?\s*(=>|if\b)", after):
                    continue  # a pattern X(name) =>
                # `| X(..)` in a match arm, but not a closure such as `|error| X(..)` or `|| X(..)`
                if (re.search(r"\|\s*$", before) and not re.search(r"\|[^|]*\|\s*$", before)) \
                        or "matches!(" in before:
                    continue
                if re.match(r"\s*\(String::new\(\)\)\s*\.code\(\)", after):
                    continue  # counted under check 3
                if re.search(r"\bErr\(\s*$", before) and re.match(r"\s*\(\w+\)\)\s*(if|=>)", after):
                    continue  # a pattern Err(X(name)) if/=>
                if "Self::" in m.group(0) and not sp.endswith("error.rs"):
                    continue
                sites.append(f"{sp}:{ln}: {m.group(1)}: {s[:150]}")
                by_variant[m.group(1)] += 1
                by_file[sp] += 1
    print("\n== 2. Non-test construction sites of variants that carry free text")
    for s in sites:
        print(s)
    lib = [s for s in sites if not s.startswith(("src/wasm_api", "src/bin/"))]
    print(f"count: {len(sites)} sites in {len(by_file)} files; library (outside src/wasm_api* "
          f"and src/bin): {len(lib)} sites in "
          f"{len({s.split(':')[0] for s in lib})} files")
    for v, c in by_variant.most_common():
        print(f"  {v}: {c}")
    failed |= bool(sites)

    # 3. Messages of library codes written by the bindings.
    print("\n== 3. Binding messages built from a code outside js_error")
    own = []
    for p in sorted(root.glob("wasm_api*")):
        for f in ([p] if p.is_file() else sorted(p.rglob("*.rs"))):
            for ln, line in non_test_lines(f.read_text()):
                if re.search(r'"\{code\}: ', line) or re.search(r"(?:MhfeError::\w+(\(String::new\(\)\)|\(0\)| \{[^}]*\}))\s*\.code\(\)", line):
                    own.append(f"{f}:{ln}: {line.strip()[:150]}")
    for o in own:
        print(o)
    print(f"count: {len(own)}")
    failed |= bool(own)

    print("\nresult:", "FAIL (Display is not the one place the messages are written)" if failed else "PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
