#!/usr/bin/env python3
"""AUD-015 R5 probe: names written in the API documents exist in the code.

    python3 docs/audits/AUD-015-harnesses/r5-build-docs/documented_symbols.py

Reads every inline code span of docs/API.md, docs/BROWSER-PACKAGE.md, README.md, SECURITY.md and
docs/releases/v0.5.1.md and checks:

- Rust paths and items (`Type`, `Type::item`, `module::item`, `function()`) against the names that
  src/ declares (fn, struct, enum, trait, type, const, static, mod, enum variants, fields);
- browser methods and options (`name()` in BROWSER-PACKAGE.md, `Class.method()`) against the names
  that web/*.d.ts declares;
- error codes (`UPPER_CASE` of 2+ parts) against the codes src/error.rs and web/*.js produce.

A name is "unknown" when no declaration of it exists anywhere in the code. Exits 1 when any
documented name is unknown. Names of other software (Node, BIP32 ...) are listed in ALLOWED.
"""
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
DOCS = ["docs/API.md", "docs/BROWSER-PACKAGE.md", "README.md", "SECURITY.md",
        "docs/releases/v0.5.1.md"]
ALLOWED = {
    # Platform and third-party names, not this project's API.
    "SharedArrayBuffer", "Uint8Array", "TypeError", "Error", "WebAssembly", "Worker", "Blob",
    "TextEncoder", "TextDecoder", "Buffer", "Promise", "crypto.getRandomValues", "getRandomValues",
    "postMessage", "structuredClone", "Atomics", "ArrayBuffer", "AbortSignal", "SecureZeroMemory",
    "explicit_bzero", "memset_s", "memset", "mlock", "VirtualLock", "Debug", "Display", "Drop",
    "Zeroizing", "Zeroize", "String", "Vec", "Option", "Result", "Some", "None", "Ok", "Err",
    "Send", "Sync", "Clone", "Copy", "Box", "Ordering", "JsError", "JsValue", "JSON.parse",
    "WebAssembly.Module", "WebAssembly.Memory", "WebAssembly.compile", "slice", "fill",
    "argon2id_hash_raw", "argon2_hash", "ARGON2_MAX_MEMORY_BITS", "ARGON2_MEMORY_TOO_MUCH",
    "UNICODE_VERSION", "RLIMIT_CORE", "PR_SET_DUMPABLE", "PR_SET_NO_NEW_PRIVS", "MADV_DONTDUMP",
    "ARGON2_OK", "From", "LICENSE",
    # A name the v0.5.1 notes say was removed ("it replaces wallet_check::new_phrase").
    "wallet_check::new_phrase", "MAP_LOCKED", "O_CREAT", "CLONE_NEWNET", "CLONE_NEWUSER", "SIGINT",
}
RUST_DECL = re.compile(
    r"\b(?:fn|struct|enum|trait|type|const|static|mod)\s+([A-Za-z_][A-Za-z0-9_]*)")
RUST_VARIANT = re.compile(r"^\s{4,}([A-Z][A-Za-z0-9]*)\s*[({,]", re.M)
RUST_FIELD = re.compile(r"^\s{4,}(?:pub(?:\([a-z]+\))?\s+)?([a-z_][a-z0-9_]*)\s*:", re.M)
TS_DECL = re.compile(r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*[?]?\s*[(:<=]")
CODE_SPAN = re.compile(r"`([^`\n]+)`")


def rust_names():
    names = set()
    for path in ROOT.glob("src/**/*.rs"):
        text = path.read_text(encoding="utf-8")
        names |= set(RUST_DECL.findall(text))
        names |= set(RUST_VARIANT.findall(text))
        names |= set(RUST_FIELD.findall(text))
        names.add(path.stem)
    return names


def ts_names():
    names = set()
    for path in list(ROOT.glob("web/*.d.ts")) + list(ROOT.glob("web/*.js")):
        names |= set(TS_DECL.findall(path.read_text(encoding="utf-8")))
    return names


def error_codes():
    codes = set()
    for path in [ROOT / "src/error.rs", *ROOT.glob("web/*.js"), *ROOT.glob("src/**/*.rs")]:
        codes |= set(re.findall(r"\"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)\"", path.read_text("utf-8")))
    for path in ROOT.glob("web/*.d.ts"):
        codes |= set(re.findall(r"\"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*)\"", path.read_text("utf-8")))
    return codes


def main():
    rust, ts, codes = rust_names(), ts_names(), error_codes()
    unknown = []
    for doc in DOCS:
        for number, line in enumerate((ROOT / doc).read_text(encoding="utf-8").splitlines(), 1):
            for span in CODE_SPAN.findall(line):
                span = span.strip()
                if span in ALLOWED or " " in span or "/" in span or span.startswith(("-", ".")):
                    continue
                # File names and environment variables are not API names.
                if re.search(r"\.(js|ts|md|c|h|rs|exe|py|sh|json|txt|wasm)$", span) or \
                        span.startswith(("CARGO_", "RUSTFLAGS", "SOURCE_", "PREBUILT_")) or \
                        span == "SHA256SUMS":
                    continue
                if re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|[A-Z]{4,}", span):
                    if span not in codes and span not in rust and span not in ts:
                        unknown.append((doc, number, span, "error code or constant"))
                    continue
                m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*(?:(?:::|\.)[A-Za-z_][A-Za-z0-9_]*)*)"
                                 r"(?:\(\))?", span)
                if not m:
                    continue
                parts = re.split(r"::|\.", m.group(1))
                last = parts[-1]
                if "::" in span:
                    pool, what = rust, "Rust name"
                elif doc in ("docs/API.md", "docs/BROWSER-PACKAGE.md") or "." in span:
                    pool, what = ts | rust, "Rust or browser name"
                else:
                    continue
                if span.endswith("()") or "::" in span or "." in span or last[0].isupper():
                    if last not in pool and last not in ALLOWED and span not in ALLOWED:
                        unknown.append((doc, number, span, what))
    for doc, number, span, what in unknown:
        print(f"{doc}:{number}: {what} `{span}` is declared nowhere in the code")
    print(f"{len(unknown)} documented names unknown.")
    return 1 if unknown else 0


if __name__ == "__main__":
    sys.exit(main())
