#!/usr/bin/env python3
"""AUD-008 local metadata, workflow and public SSH signature inspection; no build/network."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"
PUBLIC_KEY = Path("/home/sergio/.ssh/hobby-eng_signing.pub")
BASELINE_TAG = "v0.4.0"


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())
    node_manifest = json.loads((ROOT / "package.json").read_text())
    node_lock = json.loads((ROOT / "package-lock.json").read_text())
    dependency_entries = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        dependency_entries.extend(manifest.get(section, {}).items())
    for target in manifest.get("target", {}).values():
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            dependency_entries.extend(target.get(section, {}).items())
    unpinned = []
    foreign_dependencies = []
    for name, spec in dependency_entries:
        version = spec if isinstance(spec, str) else spec.get("version", "")
        if not re.fullmatch(r"=\d+\.\d+\.\d+", version):
            unpinned.append(name)
        if isinstance(spec, dict) and any(key in spec for key in ("path", "git", "branch", "tag")):
            foreign_dependencies.append(name)
    missing_lock_checksums = [package["name"] for package in lock["package"]
                              if package.get("source", "").startswith("registry+")
                              and not re.fullmatch(r"[0-9a-f]{64}", package.get("checksum", ""))]
    node_pins = {name: {"declared": version,
                         "locked": node_lock["packages"]["node_modules/" + name]["version"],
                         "installed": json.loads((ROOT / "node_modules" / name / "package.json").read_text())["version"]}
                 for name, version in node_manifest["devDependencies"].items()}
    npm_without_integrity = [name for name, package in node_lock["packages"].items()
                             if name and not package.get("integrity", "").startswith("sha512-")]
    workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
    actions = [(str(path.relative_to(ROOT)), action) for path in workflows
               for action in re.findall(r"uses:\s+([^\s#]+)", path.read_text())]
    unpinned_actions = [entry for entry in actions if not entry[1].startswith("./")
                       and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", entry[1])]
    release = (ROOT / ".github/workflows/release.yml").read_text()
    docker = (ROOT / "packaging/Dockerfile.reproducible").read_text()
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    signature_results = []
    with tempfile.TemporaryDirectory(prefix="mhfe-aud008-public-signers-") as temporary:
        allowed = Path(temporary) / "allowed_signers"
        allowed.write_text("audit namespaces=\"git\" " + PUBLIC_KEY.read_text().strip() + "\n")
        for commit in git("rev-list", f"{BASELINE_TAG}..HEAD").splitlines():
            raw = subprocess.check_output(["git", "cat-file", "-p", commit], cwd=ROOT)
            present = b"\ngpgsig " in raw.split(b"\n\n", 1)[0]
            record = {"commit": commit, "signaturePresent": present, "signatureValid": None}
            if present:
                check = subprocess.run(["git", "-c", f"gpg.ssh.allowedSignersFile={allowed}",
                                        "verify-commit", "--raw", commit], cwd=ROOT,
                                       capture_output=True, text=True)
                record.update(signatureValid=check.returncode == 0, verificationExitCode=check.returncode,
                              verificationOutput=check.stderr.strip())
            signature_results.append(record)
        tag_raw = git("cat-file", "-p", BASELINE_TAG)
        tag_check = subprocess.run(["git", "-c", f"gpg.ssh.allowedSignersFile={allowed}",
                                    "verify-tag", "--raw", BASELINE_TAG], cwd=ROOT,
                                   capture_output=True, text=True)
        tag_result = {"tag": BASELINE_TAG, "objectType": git("cat-file", "-t", BASELINE_TAG),
                      "signaturePresent": "-----BEGIN SSH SIGNATURE-----" in tag_raw,
                      "signatureValid": tag_check.returncode == 0,
                      "verificationExitCode": tag_check.returncode,
                      "verificationOutput": tag_check.stderr.strip()}
    unsigned = [entry["commit"] for entry in signature_results if not entry["signaturePresent"]]
    invalid = [entry["commit"] for entry in signature_results if entry["signatureValid"] is False]
    errors = []
    if unpinned or foreign_dependencies or missing_lock_checksums or npm_without_integrity or unpinned_actions:
        errors.append("dependency/action pin or integrity field inconsistency")
    if any(len(set(pins.values())) != 1 for pins in node_pins.values()):
        errors.append("declared, locked and installed Node versions differ")
    if invalid:
        errors.append("existing SSH commit signature did not verify with configured public key")
    if manifest["package"]["rust-version"] != toolchain["toolchain"]["channel"]:
        errors.append("Cargo rust-version differs from pinned toolchain")
    version = manifest["package"]["version"]
    citation_version = re.search(r"^version: (\S+)$", (ROOT / "CITATION.cff").read_text(), re.M)[1]
    if version != citation_version:
        errors.append("CITATION version differs from package version")
    source_files = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "package.json", "package-lock.json",
                    ".node-version", "CITATION.cff", "README.md", "THIRD_PARTY_NOTICES.md", "LICENSE",
                    "scripts/third-party-licenses.py", "scripts/build-reproducible.sh", "scripts/check.sh",
                    "scripts/package-release.sh", "scripts/check-release-artifacts.sh", "scripts/build-wasm.sh",
                    "scripts/build-argon2-wasm.sh", "packaging/Dockerfile.reproducible",
                    "packaging/Dockerfile.reproducible.dockerignore"]
    source_files.extend(str(path.relative_to(ROOT)) for path in workflows)
    record = {
        "auditId": "AUD-008", "reviewedCommit": git("rev-parse", "HEAD"),
        "publicKeySha256": digest(PUBLIC_KEY), "sourceFileSha256": {name: digest(ROOT / name) for name in source_files},
        "version": version, "citationVersion": citation_version,
        "rustVersion": toolchain["toolchain"]["channel"], "nodeVersion": (ROOT / ".node-version").read_text().strip(),
        "directCargoDependencyEntries": len(dependency_entries), "unpinnedCargoDependencies": unpinned,
        "foreignCargoDependencies": foreign_dependencies, "missingCargoLockChecksums": missing_lock_checksums,
        "cargoRegistryPackageCount": sum(bool(p.get("source", "").startswith("registry+")) for p in lock["package"]),
        "nodePins": node_pins, "npmPackagesWithoutIntegrity": npm_without_integrity,
        "externalActionOccurrences": sum(not action.startswith("./") for _, action in actions),
        "unpinnedActions": unpinned_actions,
        "releasePublishDependencies": re.search(r"^    needs: (.+)$", release, re.M)[1],
        "branchCIPolicyComment": "a release tag names a commit that CI has already checked on its branch" in ci,
        "releaseDirectlyRunsTerminalAndBrowserGates": {name: name in release or name in docker for name in
                                                     ("verify-hidden-input.py", "verify-hidden-input-windows.py", "verify-browsers.mjs")},
        "signatureResults": signature_results, "lastReleaseTag": tag_result,
        "unsignedUnreleasedCommits": unsigned, "invalidSignedCommits": invalid,
        "errors": errors, "policyFailures": ["Unreleased history contains unsigned commits."] if unsigned else [],
        "limitations": ["CI/release source inspection; no workflow dispatch, branch ruleset query or remote CI attestation check.",
                        "Node lock integrity fields checked; Cargo archive content hashes reused from retained coordinator/skeptic evidence.",
                        "Only the configured public signing key was read, and temporary allowed-signers file was removed."]}
    (EVIDENCE / "devops-static.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"version": version, "rustVersion": record["rustVersion"], "nodePins": node_pins,
                      "directCargoDependencyEntries": len(dependency_entries),
                      "externalActionOccurrences": record["externalActionOccurrences"],
                      "signatureCounts": {"checked": len(signature_results), "valid": sum(r["signatureValid"] is True for r in signature_results),
                                          "unsigned": len(unsigned), "invalid": len(invalid)},
                      "lastReleaseTag": tag_result, "unsignedUnreleasedCommits": unsigned,
                      "errors": errors, "policyFailures": record["policyFailures"]}, indent=2))
    return bool(errors or unsigned)


if __name__ == "__main__":
    raise SystemExit(main())
