#!/usr/bin/env python3
"""Inventory and lexically scan the AUD-018 browser review scope without loading its code."""

import base64
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
HOST = ROOT.parent / "multi-chain-wallet-tools"
EVIDENCE = ROOT / "docs/audits/AUD-018-evidence"
TEXT_ENDINGS = {".js", ".mjs", ".ts", ".py", ".sh", ".json", ".md"}
PATTERNS = {
    "network": (
        r"fetch\s*\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|https?://"
        r"|node:https|node:http|urllib|requests\.|socket\."
        r"|\.listen\s*\(|\.connect\s*\(|importScripts\s*\("
    ),
    "storage_and_output": (
        r"localStorage|sessionStorage|indexedDB|document\.cookie|caches\.|clipboard"
        r"|writeFile|write_text|write_bytes|console\.|innerHTML|insertAdjacentHTML"
        r"|downloadBlob|downloadText"
    ),
    "dynamic_code_and_hooks": (
        r"\beval\s*\(|new\s+Function|\bFunction\s*\(|vm\.|prototype\s*[.\[]"
        r"|Object\.defineProperty|__proto__|import\s*\(|require\s*\("
    ),
    "random_and_environment": (
        r"Math\.random|randomBytes|getRandomValues|os\.urandom|secrets\.|random\."
        r"|Date\s*\(|Date\.now|performance\.|userAgent|hardwareConcurrency"
        r"|hostname|homedir|process\.env|os\.environ|time\.|platform\."
    ),
    "encoded_payloads": (
        r"atob\s*\(|btoa\s*\(|base64Decode\s*\(|fromCharCode|base64"
        r"|\\x[0-9a-fA-F]{2}|\\u\{?[0-9a-fA-F]{4}"
    ),
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *arguments):
    result = subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True, check=True
    )
    return result.stdout.decode("utf-8")


def selected_files():
    found = {path for path in (ROOT / "web").glob("*") if path.is_file()}
    found.update(path for path in (ROOT / "scripts").glob("*") if path.is_file())
    found.add(ROOT / "packaging/mhfe-fast-mode.py")
    for folder in (ROOT / "dist", HOST / "packages/recovery-mhfe-wasm"):
        found.update(path for path in folder.rglob("*") if path.is_file())
    ui = HOST / "apps/key-derivation/src/ui"
    found.update(ui.glob("recovery-mhfe*.ts"))
    found.add(ui / "checked-mnemonic-feature.ts")
    for name in (
        "tooling/mhfe-integration.mjs",
        "tooling/vendored-mhfe-package.mjs",
        "tooling/vendored-mhfe-package.test.mjs",
        "tooling/verify-mhfe-vector.mjs",
        "tooling/verify-dependency-provenance.mjs",
        "tooling/create-verification-record.mjs",
        "apps/key-derivation/scripts/build-key-derivation-html.mjs",
        "packages/shared-ui/src/payment-qr.ts",
        "packages/export-core/src/clipboard.ts",
        "packages/export-core/src/download.ts",
        "apps/key-derivation/src/ui/app-bootstrap.ts",
    ):
        found.add(HOST / name)
    return sorted(found)


class WasmReader:
    def __init__(self, data):
        self.data = data
        self.at = 0

    def byte(self):
        result = self.data[self.at]
        self.at += 1
        return result

    def integer(self):
        value = shift = 0
        while True:
            byte = self.byte()
            value |= (byte & 127) << shift
            if byte < 128:
                return value
            shift += 7
            if shift > 70:
                raise ValueError("oversized LEB128")

    def text(self):
        length = self.integer()
        result = self.data[self.at:self.at + length].decode("utf-8")
        self.at += length
        return result

    def limits(self):
        flags = self.integer()
        self.integer()
        if flags & 1:
            self.integer()


def wasm_imports(data):
    if data[:8] != b"\x00asm\x01\x00\x00\x00":
        raise ValueError("unexpected WASM header")
    reader = WasmReader(data)
    reader.at = 8
    imports = []
    build_ids = []
    while reader.at < len(data):
        section = reader.byte()
        size = reader.integer()
        end = reader.at + size
        if section == 0:
            name = reader.text()
            if name == "mhfe-build":
                build_ids.append(data[reader.at:end].decode("utf-8"))
        elif section == 2:
            for _ in range(reader.integer()):
                module, name, kind = reader.text(), reader.text(), reader.byte()
                imports.append({"module": module, "name": name, "kind": kind})
                if kind == 0:
                    reader.integer()
                elif kind == 1:
                    reader.byte()
                    reader.limits()
                elif kind == 2:
                    reader.limits()
                elif kind == 3:
                    reader.byte()
                    reader.byte()
                elif kind == 4:
                    reader.byte()
                    reader.integer()
                else:
                    raise ValueError("unexpected import kind")
        reader.at = end
    return {"imports": imports, "buildIds": build_ids}


def manifest_check(folder, skip=()):
    path = folder / "modules.json"
    manifest = json.loads(path.read_text())
    results = []
    sections = {"runtime": manifest["runtime"], **manifest["modules"]}
    listed = {"modules.json"}
    for directory, section in sections.items():
        for name, expected in section["files"].items():
            relative = f"{directory}/{name}"
            listed.add(relative)
            if relative in skip:
                continue
            actual = sha256((folder / relative).read_bytes())
            results.append({
                "path": relative,
                "expected": expected,
                "actual": actual,
                "matches": expected == actual,
            })
    extras = sorted(
        str(p.relative_to(folder))
        for p in folder.rglob("*")
        if p.is_file() and str(p.relative_to(folder)) not in listed
    )
    return {
        "manifestSha256": sha256(path.read_bytes()),
        "buildId": manifest["buildId"],
        "files": results,
        "extraFiles": extras,
    }


def main():
    label = sys.argv[1] if len(sys.argv) == 2 else "browser-malicious-static"
    if len(sys.argv) > 2 or re.fullmatch(r"[a-z0-9-]+", label) is None:
        raise SystemExit("Usage: static-malicious-scan.py [fresh-evidence-label]")
    output = EVIDENCE / f"{label}.json"
    if output.exists():
        raise SystemExit(f"Preserving existing evidence: {output.name}; use a fresh label")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    records, hits, wasm = [], [], []
    selected = selected_files()
    compiled = {name: re.compile(pattern) for name, pattern in PATTERNS.items()}
    snapshot = {}
    for line in (EVIDENCE / "snapshot-mhfe-code-manifest.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        snapshot[name] = digest
    for path in selected:
        repository = "mhfe" if path.is_relative_to(ROOT) else "multi-chain-wallet-tools"
        root = ROOT if repository == "mhfe" else HOST
        relative = str(path.relative_to(root))
        data = path.read_bytes()
        record = {
            "repository": repository,
            "path": relative,
            "bytes": len(data),
            "sha256": sha256(data),
            "symlink": path.is_symlink(),
        }
        if repository == "mhfe" and relative in snapshot:
            record["matchesAuditSnapshot"] = record["sha256"] == snapshot[relative]
        records.append(record)
        if path.suffix == ".wasm":
            wasm.append({"repository": repository, "path": relative, **wasm_imports(data)})
        if path.suffix not in TEXT_ENDINGS:
            continue
        text = data.decode("utf-8")
        for category, pattern in compiled.items():
            for match in pattern.finditer(text):
                hits.append({
                    "repository": repository,
                    "path": relative,
                    "category": category,
                    "line": text.count("\n", 0, match.start()) + 1,
                    "token": match.group(),
                    "context": text[max(0, match.start() - 90):match.end() + 160],
                })
        if path.name.startswith("argon2-") and path.suffix == ".js":
            embedded = re.findall(r'base64Decode\("([A-Za-z0-9+/=]+)"\)', text)
            for index, payload in enumerate(embedded):
                binary = base64.b64decode(payload)
                wasm.append({
                    "repository": repository,
                    "path": relative,
                    "embeddedIndex": index,
                    "embeddedSha256": sha256(binary),
                    **wasm_imports(binary),
                })
    statuses = {
        "mhfe": git(ROOT, "status", "--short", "--", "web", "scripts",
                    "packaging/mhfe-fast-mode.py"),
        "multi-chain-wallet-tools": git(
            HOST, "status", "--short", "--",
            "apps/key-derivation/src/ui/recovery-mhfe*",
            "apps/key-derivation/src/ui/checked-mnemonic*",
            "packages/recovery-mhfe-wasm", "tooling/mhfe-integration.mjs",
            "tooling/vendored-mhfe-package.mjs",
        ),
    }
    result = {
        "capturedUtc": datetime.now(timezone.utc).isoformat(),
        "method": (
            "Read bytes, hashes, regex contexts, git status/diffs and WASM import/custom-section "
            "decoding only; never import, compile or execute the reviewed source or WASM."
        ),
        "heads": {
            "mhfe": git(ROOT, "rev-parse", "HEAD").strip(),
            "multi-chain-wallet-tools": git(HOST, "rev-parse", "HEAD").strip(),
        },
        "patterns": PATTERNS,
        "files": records,
        "hits": hits,
        "wasm": wasm,
        "workingTreeStatuses": statuses,
        "packages": {
            "upstream": manifest_check(ROOT / "dist"),
            "host": manifest_check(
                HOST / "packages/recovery-mhfe-wasm/generated", {"core/mhfe-fast-mode.py"}
            ),
        },
        "fastModeScriptSourceEqualsDist": (
            (ROOT / "packaging/mhfe-fast-mode.py").read_bytes()
            == (ROOT / "dist/core/mhfe-fast-mode.py").read_bytes()
        ),
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    for name, root in (("mhfe", ROOT), ("multi-chain-wallet-tools", HOST)):
        paths = [
            str(path.relative_to(root)) for path in selected
            if path.is_relative_to(root)
            and not str(path.relative_to(root)).startswith("dist/")
        ]
        # Deleted tracked wrappers are absent from the byte inventory but belong to the diff.
        paths.extend(
            line[3:] for line in statuses[name].splitlines() if line.startswith("D ")
        )
        # HEAD includes staged and unstaged tracked changes; untracked bytes are inventoried above.
        diff = git(root, "diff", "--no-ext-diff", "--unified=3", "HEAD", "--", *paths)
        (EVIDENCE / f"{label}-{name}-diff.txt").write_text(diff)
    print(json.dumps({
        "files": len(records),
        "lexicalMatches": len(hits),
        "wasmImportInventories": len(wasm),
        "snapshotHashMismatches": [
            r["path"] for r in records if r.get("matchesAuditSnapshot") is False
        ],
        "packageHashMismatches": {
            k: [r["path"] for r in v["files"] if not r["matches"]]
            for k, v in result["packages"].items()
        },
        "fastModeSourceEqualsDist": result["fastModeScriptSourceEqualsDist"],
        "evidence": str(output.relative_to(ROOT)),
    }))


if __name__ == "__main__":
    main()
