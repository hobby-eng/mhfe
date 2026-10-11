#!/usr/bin/env python3
"""Read/hash browser sources and decode import surfaces without executing reviewed code."""

import base64
import importlib.util
import json
import re
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = ROOT / "docs/audits/AUD-019-evidence"
LEGACY = ROOT / "docs/audits/AUD-018-harnesses/browser/static-malicious-scan.py"


def main():
    spec = importlib.util.spec_from_file_location("retained_static_helpers", LEGACY)
    scan = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scan)
    output = EVIDENCE / "browser-inventory.json"
    if output.exists():
        raise SystemExit("Preserving browser-inventory.json")
    before = (ROOT / "dist/modules.json").read_bytes()
    snapshot = {}
    for line in (EVIDENCE / "initial-mhfe-code-manifest.txt").read_text().splitlines():
        digest, path = line.split("  ", 1)
        snapshot[path] = digest
    records, hits, wasm = [], [], []
    for path in scan.selected_files():
        upstream = path.is_relative_to(ROOT)
        repository = "mhfe" if upstream else "multi-chain-wallet-tools"
        relative = str(path.relative_to(ROOT if upstream else scan.HOST))
        data = path.read_bytes()
        item = {"repository": repository, "path": relative, "bytes": len(data),
                "sha256": scan.sha256(data), "symlink": path.is_symlink()}
        if upstream and relative in snapshot:
            item["matchesAuditSnapshot"] = item["sha256"] == snapshot[relative]
        records.append(item)
        if path.suffix == ".wasm":
            wasm.append({"repository": repository, "path": relative,
                         **scan.wasm_imports(data)})
        if path.suffix not in scan.TEXT_ENDINGS:
            continue
        text = data.decode("utf-8")
        for category, pattern in scan.PATTERNS.items():
            for match in re.finditer(pattern, text):
                hits.append({"repository": repository, "path": relative,
                             "category": category,
                             "line": text.count("\n", 0, match.start()) + 1,
                             "token": match.group(),
                             "context": text[max(0, match.start() - 90):match.end() + 160]})
        if path.name.startswith("argon2-") and path.suffix == ".js":
            for payload in re.findall(r'base64Decode\("([A-Za-z0-9+/=]+)"\)', text):
                binary = base64.b64decode(payload)
                wasm.append({"repository": repository, "path": relative,
                             "embeddedSha256": scan.sha256(binary),
                             **scan.wasm_imports(binary)})
    packages = {
        "upstream": scan.manifest_check(ROOT / "dist"),
        "host": scan.manifest_check(scan.HOST / "packages/recovery-mhfe-wasm/generated",
                                    {"core/mhfe-fast-mode.py"}),
    }
    stable = before == (ROOT / "dist/modules.json").read_bytes()
    result = {
        "capturedUtc": datetime.now(timezone.utc).isoformat(),
        "reviewedCommit": scan.git(ROOT, "rev-parse", "HEAD").strip(),
        "retainedHelperSha256": scan.sha256(LEGACY.read_bytes()),
        "method": "Read/hash/lexical scan and WASM import decoding only; no reviewed code executes.",
        "manifestStableDuringRead": stable,
        "files": records, "patterns": scan.PATTERNS, "hits": hits, "wasm": wasm,
        "packages": packages,
    }
    output.write_text(json.dumps(result, indent=2) + "\n")
    mismatches = [r["path"] for r in records if r.get("matchesAuditSnapshot") is False]
    package_mismatches = {
        key: [r["path"] for r in value["files"] if not r["matches"]]
        for key, value in packages.items()
    }
    print(json.dumps({"files": len(records), "lexicalMatches": len(hits),
                      "wasmSurfaces": len(wasm), "manifestStable": stable,
                      "snapshotMismatches": mismatches,
                      "packageMismatches": package_mismatches,
                      "buildIds": {k: v["buildId"] for k, v in packages.items()}}))
    return 0 if stable and not mismatches and not any(package_mismatches.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
