#!/usr/bin/env python3
"""AUD-008: bounded local-only manifest, cache and release-gate review; no builds."""

import hashlib
import json
from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parents[3]
CACHE = ROOT.parent / "workingspace/cargo/registry/cache"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    dependencies = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        dependencies.extend(manifest.get(section, {}).items())
    for target in manifest.get("target", {}).values():
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            dependencies.extend(target.get(section, {}).items())
    unpinned = []
    for name, specification in dependencies:
        version = specification if isinstance(specification, str) else specification.get("version")
        if not version or not re.fullmatch(r"=\d+\.\d+\.\d+", version):
            unpinned.append(name)

    registry = [p for p in lock["package"] if p.get("source", "").startswith("registry+")]
    cache_matches = 0
    cache_missing = []
    cache_mismatches = []
    for package in registry:
        name = f"{package['name']}-{package['version']}.crate"
        archives = list(CACHE.glob(f"*/{name}"))
        if not archives:
            cache_missing.append(name)
            continue
        for archive in archives:
            if digest(archive) != package.get("checksum"):
                cache_mismatches.append(name)
        cache_matches += 1

    workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
    actions = []
    for workflow in workflows:
        actions.extend(re.findall(r"uses:\s+([^\s#]+)", workflow.read_text()))
    unpinned_actions = [action for action in actions if not action.startswith("./")
                       and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", action)]
    release = (ROOT / ".github/workflows/release.yml").read_text()
    docker = (ROOT / "packaging/Dockerfile.reproducible").read_text()
    missing_gates = [command for command in ("verify-hidden-input.py", "verify-browsers.mjs")
                     if command not in release and command not in docker]
    version = manifest["package"]["version"]
    citation_version = re.search(r"^version: (\S+)$", (ROOT / "CITATION.cff").read_text(), re.M)[1]
    node_package = json.loads((ROOT / "package.json").read_text())
    node_lock = json.loads((ROOT / "package-lock.json").read_text())
    node_pin_mismatches = [name for name, value in node_package["devDependencies"].items()
                          if node_lock["packages"]["node_modules/" + name]["version"] != value]
    files = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".node-version",
             "package.json", "package-lock.json", "CITATION.cff", "LICENSE",
             "THIRD_PARTY_NOTICES.md", "scripts/third-party-licenses.py",
             "scripts/build-reproducible.sh", "scripts/package-release.sh",
             "scripts/check-release-artifacts.sh", "packaging/Dockerfile.reproducible",
             "packaging/Dockerfile.reproducible.dockerignore", "scripts/build-wasm.sh",
             "scripts/build-argon2-wasm.sh", "vendor/phc-winner-argon2.md",
             "vendor/eff-large-wordlist.md"]
    files.extend(str(path.relative_to(ROOT)) for path in workflows)
    print(json.dumps({
        "auditId": "AUD-008",
        "noBuildsOrNetwork": True,
        "directCargoDependencyEntries": len(dependencies),
        "unpinnedDirectCargoDependencies": unpinned,
        "cargoRegistryPackages": len(registry),
        "cargoArchiveChecksumsMatched": cache_matches,
        "cargoArchivesUnavailableLocally": cache_missing,
        "cargoArchiveChecksumMismatches": cache_mismatches,
        "workflowExternalActionOccurrences": len([a for a in actions if not a.startswith('./')]),
        "unpinnedExternalActions": unpinned_actions,
        "version": version,
        "citationVersion": citation_version,
        "nodeDirectPinMismatches": node_pin_mismatches,
        "releasePublishDependencies": re.search(r"^    needs: (.+)$", release, re.M)[1],
        "terminalAndBrowserReleaseGatesMissing": missing_gates,
        "fileSha256": {name: digest(ROOT / name) for name in files},
        "limitations": [
            "Workflow review is source inspection, not a dispatched GitHub Actions run.",
            "Matching local crate archives proves the checked lockfile bytes, not vulnerability absence.",
            "No independent canonical rebuild or byte comparison was performed.",
        ],
    }, indent=2))
    return bool(unpinned or cache_mismatches or unpinned_actions or node_pin_mismatches
                or version != citation_version or missing_gates)


if __name__ == "__main__":
    raise SystemExit(main())
