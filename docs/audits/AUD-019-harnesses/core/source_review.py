#!/usr/bin/env python3
"""AUD-019 bounded inventory, public verifier oracle and historical annotation checks."""

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SPEC = ROOT.parent / "mhfe_spec"
CORE = (
    "mhfe", "feistel", "packing", "password", "phrase", "suite", "container",
    "detection", "rekey", "rehearsal", "hidden", "operation", "memory", "random",
    "word_wishes", "search", "repair", "wallet", "wallet_check", "new_password",
    "check_word", "strength", "engine/native", "engine/browser", "engine/ffi",
)
STATES = (
    ("4d48464520616d62000000004dda455a85b22f09e43e0ae5de9322dce19210ad", [12, 21]),
    ("4d48464520616d626967756f00000000d7215b3cc350c32cc955fd4e3e272edf", [15, 21]),
    ("4d48464520616d626967756f7573207400000000643a0b3e565fd3c1659f6749", [18, 21]),
)


def git(directory, *args):
    result = subprocess.run(
        ["git", "-C", str(directory), *args], capture_output=True, check=False
    )
    return result.returncode, result.stdout.decode().strip()


def unavailable(document):
    found = {}
    if isinstance(document, dict):
        for key, value in document.items():
            if key == "unavailableCommits":
                found.update(value)
            found.update(unavailable(value))
    elif isinstance(document, list):
        for value in document:
            found.update(unavailable(value))
    return found


def pointer(document, path):
    value = document
    for key in path.split("/")[1:]:
        value = value[key]
    return value


def main():
    assert git(ROOT, "rev-parse", "HEAD")[1] == "66f142566464255e331763966b00ea1681c2dabd"
    rust = sorted((ROOT / "src").rglob("*.rs"))
    print(f"Rust source inventory: {len(rust)} files, {sum(len(p.read_bytes()) for p in rust)} bytes")
    baseline_path = ROOT / "docs/audits/AUD-018-evidence/closeout-mhfe-code-manifest.txt"
    if not baseline_path.exists():
        baseline_path = ROOT / "docs/audits/AUD-018-evidence/snapshot-mhfe-code-manifest.txt"
    baseline = {}
    if baseline_path.exists():
        for line in baseline_path.read_text().splitlines():
            digest, path = line.split("  ", 1)
            baseline[path] = digest
        print(f"AUD-018 manifest: {baseline_path.name} {hashlib.sha256(baseline_path.read_bytes()).hexdigest()}")
    identities = 0
    for module in CORE:
        name = f"src/{module}.rs"
        content = (ROOT / name).read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        same = baseline.get(name) == digest
        identities += same
        print(f"core-file {name} sha256={digest} identicalToAUD018={str(same).lower()}")
    print(f"Core identity: {identities}/{len(CORE)} identical to retained AUD-018 manifest")

    for text, expected in STATES:
        state = bytes.fromhex(text)
        found = [words for words in (12, 15, 18, 21) if (
            state[words // 3 * 4:] == hashlib.sha256(state[:words // 3 * 4]).digest()[:32 - words // 3 * 4]
        )]
        assert found == expected, (text, found, expected)
        print(f"Public verifier oracle: {text} shortLayouts={found}")

    spec_head = git(SPEC, "rev-parse", "HEAD")[1]
    spec_tag = git(SPEC, "rev-parse", "v0.6.0^{}")[1]
    tag_text = subprocess.run(["git", "-C", str(SPEC), "show", "v0.6.0:README.md"], capture_output=True, check=True).stdout
    current_text = (SPEC / "README.md").read_bytes()
    def protocol_text(text):
        return text.split(b"## Specification\n", 1)[1].split(b"## References\n", 1)[0]
    assert protocol_text(tag_text) == protocol_text(current_text)
    print(f"Spec HEAD={spec_head}, tagCommit={spec_tag}, READMEsha256={hashlib.sha256(current_text).hexdigest()}, tagProtocolTextIdentical=true, wholeREADMEidentical={str(tag_text == current_text).lower()}")
    annotations = 0
    fields = 0
    for number in (2, 8):
        report = next((ROOT / "docs/audits").glob(f"audit-{number:02d}-*.json"))
        document = json.loads(report.read_text())
        for commit, annotation in unavailable(document).items():
            assert git(SPEC, "cat-file", "-e", f"{commit}^{{commit}}")[0] != 0
            assert annotation["sameTreeInCurrentHistory"] is False
            assert annotation["nearestHasReviewedTree"] is False
            assert git(SPEC, "cat-file", "-e", f"{annotation['nearestCurrentCommit']}^{{commit}}")[0] == 0
            for field in annotation["fields"]:
                assert pointer(document, field) == commit
                fields += 1
            annotations += 1
            print(f"Historical annotation {report.name}: unavailable={commit}, fields={len(annotation['fields'])}, explicitlyNoEquivalentTree=true")
    print(f"Historical source bindings: {annotations} explicit annotations cover {fields} unavailable fields; original bytes were not restored")
    print("PASS bounded source review; no Argon2, full vector replay, build or network")


if __name__ == "__main__":
    main()
