#!/usr/bin/env python3
"""AUD-024 verifier scan: panic macros (assert!, assert_eq!, assert_ne!, unreachable!, todo!,
unimplemented!) left in shipped Rust code of src/, after removing items gated by #[cfg(test)].

Usage (from the repository root): python3 scan_asserts.py src
Prints file:line and the line for each hit; exit status 1 when any hit is found.
"""
import pathlib
import re
import sys

MACRO = re.compile(r"\b(assert|assert_eq|assert_ne|unreachable|todo|unimplemented)!")


def blank_comments_and_strings(text: str) -> str:
    """Replaces comments and string literal contents with spaces, keeping newlines."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif text.startswith('r#"', i) or text.startswith('r"', i):
            hashes = 1 if text.startswith('r#"', i) else 0
            start = i + 2 + hashes
            end_token = '"' + "#" * hashes
            j = text.find(end_token, start)
            j = n if j < 0 else j + len(end_token)
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j += 1
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif c == "'" and i + 2 < n and (text[i + 2] == "'" or (text[i + 1] == "\\" and "'" in text[i + 2 : i + 12])):
            j = text.find("'", i + 2 if text[i + 1] != "\\" else i + 3) + 1
            out.append(" " * (j - i))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def strip_cfg_test(clean: str) -> str:
    """Blanks every item that follows #[cfg(test)]: up to its matching closing brace or semicolon."""
    result = list(clean)
    for match in re.finditer(r"#\[cfg\(test\)\]", clean):
        i = match.end()
        depth = 0
        while i < len(clean):
            ch = clean[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            elif ch == ";" and depth == 0:
                i += 1
                break
            i += 1
        for k in range(match.start(), i):
            if result[k] != "\n":
                result[k] = " "
    return "".join(result)


def test_only_files(root: pathlib.Path) -> set:
    """Files whose module is declared under #[cfg(test)] (`#[cfg(test)] mod name;`)."""
    files = set()
    for path in root.rglob("*.rs"):
        text = path.read_text()
        for m in re.finditer(r"#\[cfg\(test\)\]\s*(?:pub(?:\(crate\))?\s+)?mod\s+(\w+)\s*;", text):
            name = m.group(1)
            base = path.parent if path.name in ("lib.rs", "main.rs", "mod.rs") else path.with_suffix("")
            for candidate in (base / f"{name}.rs", base / name / "mod.rs"):
                if candidate.exists():
                    files.add(candidate.resolve())
            sub = base / name
            if sub.is_dir():
                files.update(p.resolve() for p in sub.rglob("*.rs"))
    return files


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "src")
    skip = test_only_files(root)
    hits = 0
    for path in sorted(root.rglob("*.rs")):
        if path.resolve() in skip:
            continue
        original = path.read_text().splitlines()
        shipped = strip_cfg_test(blank_comments_and_strings(path.read_text()))
        for number, line in enumerate(shipped.splitlines(), start=1):
            if MACRO.search(line):
                hits += 1
                print(f"{path}:{number}: {original[number - 1].strip()}")
    print(f"{hits} panic macro(s) in shipped code; test-only files skipped: {len(skip)}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
