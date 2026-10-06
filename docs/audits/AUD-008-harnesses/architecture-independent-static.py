#!/usr/bin/env python3
"""Bounded source-consistency probes for AUD-008; no compilation or secret inputs."""

import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]


def read(name):
    return (ROOT / name).read_text(encoding="utf-8")


def constant(text, name):
    match = re.search(r"\bconst " + name + r"(?::\s*\w+)?\s*=\s*(\d+)", text)
    if match is None:
        raise ValueError("constant not found: " + name)
    return int(match.group(1))


def main():
    wasm = read("src/wasm_api.rs")
    exports = {
        js_name or rust_name
        for js_name, rust_name in re.findall(
            r"#\[wasm_bindgen(?:\(js_name = (\w+)\))?\]\s*pub fn (\w+)", wasm
        )
    }
    calls = set(re.findall(r"wasm_bindgen\.(\w+)\(", read("web/mhfe-worker.js")))
    calls.discard("initSync")
    suite = read("src/suite.rs")
    client = read("web/client.js")
    error = read("src/error.rs").split("pub const fn code", 1)[1]
    codes = set(re.findall(r'=> "([A-Z][A-Z0-9_]+)"', error))
    variants = set(re.findall(r"Self::(\w+)", error))
    exit_variants = set(re.findall(r"MhfeError::(\w+)", read("src/bin/mhfe/exit.rs")))
    documented_codes = set(re.findall(r"`([A-Z][A-Z0-9_]+)`", read("docs/API.md")))
    checks = [
        {
            "name": "worker_calls_resolve_to_declared_wasm_exports",
            "passed": calls <= exports,
            "calls": sorted(calls),
            "declaredExports": sorted(exports),
            "missing": sorted(calls - exports),
        },
        {
            "name": "browser_and_rust_limits_agree",
            "passed": all(
                constant(suite, name) == constant(client, name)
                for name in ("MAX_PIM", "MAX_MEMORY_LEVEL")
            )
            and constant(read("src/engine/browser.rs"), "HIGHEST_BROWSER_MEMORY_LEVEL")
            == constant(client, "HIGHEST_BROWSER_MEMORY_LEVEL"),
            "maxPim": constant(suite, "MAX_PIM"),
            "maxMemoryLevel": constant(suite, "MAX_MEMORY_LEVEL"),
            "highestBrowserMemoryLevel": constant(client, "HIGHEST_BROWSER_MEMORY_LEVEL"),
        },
        {
            "name": "eff_wordlist_dimensions_agree",
            "passed": constant(read("src/bin/mhfe/check_word.rs"), "LIST_SIZE")
            == constant(read("src/bin/mhfe/diceware.rs"), "LIST_SIZE")
            == len(read("vendor/eff-large-wordlist/eff_large_wordlist.txt").splitlines()),
            "listSize": constant(read("src/bin/mhfe/diceware.rs"), "LIST_SIZE"),
        },
        {
            "name": "every_core_error_variant_has_cli_exit_mapping",
            "passed": variants == exit_variants,
            "variantCount": len(variants),
            "missingFromCli": sorted(variants - exit_variants),
            "unknownInCli": sorted(exit_variants - variants),
        },
        {
            "name": "every_core_error_code_is_documented",
            "passed": codes <= documented_codes,
            "codeCount": len(codes),
            "missingFromApiDocument": sorted(codes - documented_codes),
        },
    ]
    # This is a source inventory, not a Rust parser or a generated-binding/runtime check.
    sources = sorted(
        {str(path.relative_to(ROOT)) for path in (ROOT / "src").rglob("*.rs")}
        | {
            "Cargo.toml",
            "build.rs",
            "web/client.js",
            "web/client.d.ts",
            "web/mhfe-worker.js",
            "scripts/build-wasm.sh",
            "docs/API.md",
            "vendor/eff-large-wordlist/eff_large_wordlist.txt",
        }
    )
    source_hashes = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources
    }
    canonical = json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()
    result = {
        "reviewedCommit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "checks": checks,
        "sourceHashes": source_hashes,
        "sourceFingerprint": hashlib.sha256(canonical).hexdigest(),
        "limits": [
            "Source regexes identify direct, declared imports/exports only.",
            "No Cargo, build, Argon2, vector replay, browser, or terminal operation was executed.",
            "Current source equality cannot prove absence of future constant drift.",
        ],
    }
    print(json.dumps(result, indent=2))
    return 0 if all(check["passed"] for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
