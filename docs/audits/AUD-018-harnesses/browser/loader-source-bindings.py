#!/usr/bin/env python3
"""Compare fresh browser classes and the joined worker with their current local source bytes."""

import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = ROOT / "docs/audits/AUD-018-evidence"
OUTPUT = EVIDENCE / "browser-loader-source-bindings.json"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    if OUTPUT.exists():
        raise SystemExit("Preserving existing browser-loader-source-bindings.json")
    build = json.loads((ROOT / "dist/modules.json").read_text())["buildId"]
    stamp = re.compile(r'^((?:export )?const [A-Z0-9_]*BUILD_ID = )"development";$', re.M)
    pairs = [("web/runtime.js", "dist/runtime/runtime.js"),
             ("web/runtime.d.ts", "dist/runtime/runtime.d.ts")]
    for name, directory in (("client", "core"), ("repair", "repair"),
                            ("passwords", "passwords"), ("wallet", "wallet")):
        for suffix in ("js", "d.ts"):
            pairs.append((f"web/{name}.{suffix}", f"dist/{directory}/{name}.{suffix}"))
    records = []
    for source, generated in pairs:
        original = (ROOT / source).read_bytes()
        expected = stamp.sub(r'\g<1>"' + build + '";', original.decode()).encode()
        actual = (ROOT / generated).read_bytes()
        records.append({
            "source": source, "sourceSha256": sha256(original),
            "generated": generated, "generatedSha256": sha256(actual),
            "matchesSourceAfterBuildStamp": expected == actual,
        })
    pieces = ["target/wasm-bindgen/mhfe.js", "web/argon2-engine.js",
              "web/worker-runtime.js", "web/core-worker.js", "web/repair-worker.js",
              "web/passwords-worker.js", "web/wallet-worker.js", "web/worker-start.js"]
    sources = [{"path": path, "sha256": sha256((ROOT / path).read_bytes())}
               for path in pieces]
    joined = b"".join((ROOT / path).read_bytes() for path in pieces).decode()
    expected = stamp.sub(r'\g<1>"' + build + '";', joined).encode()
    actual = (ROOT / "dist/runtime/worker.js").read_bytes()
    worker = {
        "sources": sources, "generatedSha256": sha256(actual),
        "matchesOrderedSourceJoinAfterBuildStamp": expected == actual,
    }
    result = {
        "method": "Read and compare text bytes only; no JavaScript or WASM is executed.",
        "buildId": build, "classes": records, "worker": worker,
        "limitations": [
            "The local bindgen output is an input to the join, not a trusted external reference.",
            "This comparison does not authenticate the toolchain or disassemble the WASM body.",
        ],
    }
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n")
    passed = all(r["matchesSourceAfterBuildStamp"] for r in records)
    passed = passed and worker["matchesOrderedSourceJoinAfterBuildStamp"]
    print(json.dumps({"classFiles": len(records), "workerPieces": len(pieces),
                      "allMatch": passed, "buildId": build,
                      "evidence": str(OUTPUT.relative_to(ROOT))}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
