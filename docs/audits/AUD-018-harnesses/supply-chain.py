#!/usr/bin/env python3
"""Inspect build configuration and verify installed tooling against pinned npm archives."""

import base64
import datetime
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tomllib
import urllib.request
from pathlib import Path


class SupplyChainReview:
    def __init__(self):
        self._root = Path(__file__).resolve().parents[3]
        self._evidence = self._root / "docs/audits/AUD-018-evidence"

    @staticmethod
    def _sha(data):
        return hashlib.sha256(data).hexdigest()

    def _git(self, *arguments):
        result = subprocess.run(["git", *arguments], cwd=self._root, capture_output=True,
                                text=True, timeout=30)
        return {"argv": ["git", *arguments], "exitCode": result.returncode,
                "output": result.stdout.strip()}

    def run(self):
        inspected = [self._root / "build.rs", self._root / "Cargo.toml",
                     self._root / "Cargo.lock", self._root / "package.json",
                     self._root / "package-lock.json", self._root / "rust-toolchain.toml"]
        for folder in ["packaging", ".github"]:
            inspected += [p for p in (self._root / folder).rglob("*") if p.is_file()]
        inspected += list((self._root / "scripts").glob("*.sh"))
        findings = []
        cargo = tomllib.loads((self._root / "Cargo.toml").read_text())
        lock = tomllib.loads((self._root / "Cargo.lock").read_text())
        nonregistry = [p["name"] for p in lock["package"]
                       if p.get("source") not in [None, "registry+https://github.com/rust-lang/crates.io-index"]]
        assert not nonregistry, nonregistry
        assert not any(key in cargo for key in ["patch", "replace", "workspace"])
        runtime_manifest = json.loads((self._root / "package.json").read_text())
        assert runtime_manifest["scripts"] == {
            "format": "prettier --write .", "format:check": "prettier --check .",
            "check:browsers": "node scripts/verify-browsers.mjs"}

        config_paths = []
        for parent in [self._root, self._root.parent, *self._root.parent.parents]:
            config_paths += [parent / ".cargo/config", parent / ".cargo/config.toml"]
        cargo_home = Path(os.environ.get("CARGO_HOME", self._root.parent / "workingspace/cargo"))
        config_paths += [cargo_home / "config", cargo_home / "config.toml"]
        configurations = []
        for path in dict.fromkeys(config_paths):
            if path.is_file():
                # Configs can contain credentials: retain only key names and a byte binding.
                content = path.read_bytes()
                keys = sorted(tomllib.loads(content.decode()).keys())
                configurations.append({"path": str(path), "sha256": self._sha(content), "topLevelKeys": keys})
        git_config = []
        for pattern in [r"^core\.(hooksPath|fsmonitor|sshCommand)$", r"^filter\.",
                        r"^include", r"^url\..*\.insteadOf$"]:
            # Names identify executable configuration without printing arbitrary config secrets.
            git_config.append(self._git("config", "--name-only", "--get-regexp", pattern))
        hooks = self._root / ".git/hooks"
        active_hooks = sorted(path.name for path in hooks.glob("*")
                              if path.is_file() and not path.name.endswith(".sample"))
        replacements = self._git("for-each-ref", "--format=%(refname)", "refs/replace")
        assert not active_hooks and not replacements["output"], (active_hooks, replacements)
        injection_variables = [name for name in ["LD_PRELOAD", "LD_AUDIT", "NODE_OPTIONS",
                                                "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                                                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"]
                               if os.environ.get(name)]

        npm_lock = json.loads((self._root / "package-lock.json").read_text())
        package_results = []
        for relative, package in npm_lock["packages"].items():
            if not relative:
                continue
            url = package["resolved"]
            assert url.startswith("https://registry.npmjs.org/")
            with urllib.request.urlopen(url, timeout=30) as response:
                assert response.geturl().startswith("https://registry.npmjs.org/")
                archive = response.read(32 * 1024 * 1024 + 1)
            assert len(archive) <= 32 * 1024 * 1024
            algorithm, encoded = package["integrity"].split("-", 1)
            assert algorithm == "sha512"
            assert hashlib.sha512(archive).digest() == base64.b64decode(encoded)
            expected = {}
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as packed:
                for item in packed.getmembers():
                    if item.isfile():
                        assert item.name.startswith("package/")
                        expected[item.name[len("package/"):]] = self._sha(packed.extractfile(item).read())
            installed = self._root / relative
            actual = {str(path.relative_to(installed)): self._sha(path.read_bytes())
                      for path in installed.rglob("*") if path.is_file()}
            differences = sorted(name for name in set(expected) | set(actual)
                                 if expected.get(name) != actual.get(name))
            if differences:
                findings.append({"package": relative, "mismatches": differences})
            package_results.append({"package": relative, "version": package["version"],
                                    "url": url, "archiveSha256": self._sha(archive),
                                    "sha512IntegrityPassed": True, "files": len(actual),
                                    "archiveFiles": len(expected), "mismatches": differences})

        pattern = re.compile(r"https?://[^\s\"'<>]+|\b(?:curl|wget|eval|exec|base64)\b|(?:Command::new|process\.env)")
        hits = []
        for path in inspected:
            for number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if pattern.search(line):
                    hits.append({"file": str(path.relative_to(self._root)), "line": number,
                                 "text": line.strip()})
        record = {
            "auditId": "AUD-018", "capturedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "fileHashes": {str(path.relative_to(self._root)): self._sha(path.read_bytes()) for path in inspected},
            "cargoNonRegistryPackages": nonregistry, "cargoManifestOverrideTables": [],
            "cargoConfigurations": configurations, "gitExecutableConfigNames": git_config,
            "activeGitHooks": active_hooks, "gitReplacementRefs": replacements,
            "loaderInjectionVariableNames": injection_variables,
            "npmPackages": package_results, "buildPatternCandidates": hits,
            "unexpectedToolingBytes": findings,
            "limits": ["Registry equality is pinned-package integrity, not a complete upstream code audit.",
                       "The existing OS, toolchain binaries, browser executables, firmware and account state are not certified.",
                       "Local source/lock hashes can share a compromised trust origin; no pre-incident independent backup was provided."]}
        (self._evidence / "supply-chain.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps({"npmPackages": len(package_results),
                          "installedFiles": sum(item["files"] for item in package_results),
                          "unexpectedToolingBytes": len(findings), "cargoConfigurations": configurations,
                          "activeGitHooks": active_hooks, "loaderInjectionVariableNames": injection_variables}))
        return bool(findings)


if __name__ == "__main__":
    raise SystemExit(SupplyChainReview().run())
