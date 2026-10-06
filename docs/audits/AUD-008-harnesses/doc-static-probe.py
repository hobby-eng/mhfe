#!/usr/bin/env python3
"""Read-only documentation and packaged-link checks for MHFE AUD-008."""

import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"
SCOPE = (
    "README.md",
    "SECURITY.md",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "docs/API.md",
    "docs/BROWSER-PACKAGE.md",
    "docs/releases/unreleased.md",
    "src/wallet_check.rs",
    "src/repair.rs",
    "src/rehearsal.rs",
    "src/bin/mhfe/main.rs",
    "src/bin/mhfe/diceware.rs",
    "src/bin/mhfe/terminal.rs",
    "scripts/build-wasm.sh",
    "scripts/package-release.sh",
)
# The API and integration guide use ordinary inline Markdown file links.
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)\s]+)\)")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_links(path):
    result = []
    for match in LINK.finditer(path.read_text()):
        target = match.group(1)
        if target.startswith(("https:", "http:", "#", "mailto:")):
            continue
        filename = target.split("#", 1)[0]
        result.append(
            {
                "target": target,
                "exists": (path.parent / filename).exists(),
                "line": path.read_text()[: match.start()].count("\n") + 1,
            }
        )
    return result


def main():
    snapshot = json.loads((EVIDENCE / "snapshot.json").read_text())
    hashes = {name: digest(ROOT / name) for name in SCOPE}
    binding = {
        name: hashes[name] == snapshot["mhfe"]["files"][name] for name in SCOPE
    }
    spec = ROOT.parent / "mhfe_spec/README.md"
    spec_hash = digest(spec)
    binding["../mhfe_spec/README.md"] = (
        spec_hash == snapshot["specification"]["files"]["README.md"]
    )
    print(json.dumps({"probe": "source-binding", "files": binding}, sort_keys=True))
    if not all(binding.values()):
        return 2

    failures = []
    api = (ROOT / "docs/API.md").read_text()
    repair = (ROOT / "src/repair.rs").read_text()
    readme = (ROOT / "README.md").read_text()
    source_check = (ROOT / "src/wallet_check.rs").read_text()
    stale = "specification does not define yet" in readme or (
        "not yet part of the specification" in source_check
    )
    if stale:
        failures.append("stale-source-profile-status")
    wrong_card = "more damage, or a card of another plate, gives" in api or (
        "Fails when the damage is more than the repair words can repair" in repair
    )
    if wrong_card:
        failures.append("wrong-card-rejection-guarantee")
    for name in ("README.md", "SECURITY.md", "docs/API.md", "docs/BROWSER-PACKAGE.md"):
        links = local_links(ROOT / name)
        print(json.dumps({"probe": "source-local-links", "file": name, "links": links}))
        if any(not link["exists"] for link in links):
            failures.append("source-local-link:" + name)

    # build-wasm.sh copies BROWSER-PACKAGE.md unchanged into dist/README.md, and
    # package-release.sh copies dist/ unchanged into the browser archive.
    packaged_links = local_links(ROOT / "dist/README.md")
    print(json.dumps({"probe": "browser-package-local-links", "links": packaged_links}))
    if any(not link["exists"] for link in packaged_links):
        failures.append("browser-package-relative-link")

    executable = ROOT / "target/debug/mhfe"
    helps = {}
    for command in ([], ["encrypt"], ["decrypt"], ["check"], ["new"], ["repair"],
                    ["repair-words"], ["password"], ["rekey"], ["wallets"], ["serve"]):
        result = subprocess.run(
            [str(executable), *command, "--help"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
        name = command[0] if command else "main"
        helps[name] = {"exitCode": result.returncode, "text": result.stdout}
        print(json.dumps({"probe": "help", "command": name, **helps[name]}))
        if result.returncode:
            failures.append("help-exit:" + name)
    hidden = "hidden prompts" in helps["main"]["text"]
    print(json.dumps({"probe": "main-help-input-description", "saysHiddenPrompts": hidden}))
    summary = {
        "auditId": "AUD-008",
        "commit": snapshot["mhfe"]["commit"],
        "sourceFingerprint": snapshot["mhfe"]["sourceFingerprint"],
        "scopeHashes": hashes,
        "specSha256": spec_hash,
        "productionExecutableSha256": digest(executable),
        "failures": failures,
        "helpExecutions": len(helps),
        "noArgon2": True,
    }
    print(json.dumps({"probe": "summary", **summary}, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
