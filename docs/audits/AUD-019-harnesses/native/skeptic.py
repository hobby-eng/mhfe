#!/usr/bin/env python3
"""AUD-019 read-only bindings for the independent core/browser skeptic review."""

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class SkepticBindings:
    def __init__(self):
        self.root = Path(__file__).resolve().parents[4]
        self.evidence = self.root / "docs/audits/AUD-019-evidence"

    @staticmethod
    def digest(data):
        return hashlib.sha256(data).hexdigest()

    def git(self, root, *arguments):
        return subprocess.check_output(["git", *arguments], cwd=root, text=True).rstrip("\n")

    def bind(self, path):
        data = (self.root / path).read_bytes()
        return {"path": path, "sha256": self.digest(data), "bytes": len(data)}

    def execute(self):
        paths = [
            "SECURITY.md",
            "src/repair.rs",
            "src/wasm_api/repair.rs",
            "src/bin/mhfe/container_repair.rs",
            "src/rehearsal.rs",
            "src/rekey.rs",
            "src/wasm_api/core.rs",
            "web/core-worker.js",
            "web/client.js",
            "scripts/check.sh",
            "scripts/verify-browser-package.mjs",
            "scripts/verify-browsers.mjs",
            "../mhfe_spec/README.md",
            "../multi-chain-wallet-tools/AGENTS.md",
            "../multi-chain-wallet-tools/apps/key-derivation/src/ui/recovery-mhfe-confirm-again.ts",
            "../multi-chain-wallet-tools/apps/key-derivation/src/ui/recovery-mhfe-rekey.ts",
            "../multi-chain-wallet-tools/apps/key-derivation/tests/recovery-mhfe-rekey.test.ts",
            "../multi-chain-wallet-tools/packages/recovery-mhfe-wasm/README.md",
            "docs/audits/AUD-019-harnesses/browser/rekey-retry.mjs",
            "docs/audits/AUD-019-harnesses/core/public_preflight.rs",
        ]
        evidence_paths = [
            "docs/audits/AUD-019-evidence/initial.json",
            "docs/audits/AUD-019-evidence/release-check.command.json",
            "docs/audits/AUD-019-evidence/release-check.log",
            "docs/audits/AUD-019-evidence/remote-release-run.json",
            "docs/audits/AUD-019-evidence/remote-release-checks.log",
            "docs/audits/AUD-019-evidence/browser-rekey-retry-accepted.command.json",
            "docs/audits/AUD-019-evidence/browser-rekey-retry-accepted.log",
            "docs/audits/AUD-019-evidence/browser-loader-source-bindings.json",
            "docs/audits/AUD-019-evidence/core-preflight-compile.command.json",
            "docs/audits/AUD-019-evidence/core-public-preflight.log",
        ]
        remote = (self.root / evidence_paths[4]).read_text().splitlines()
        expected = {
            "stated15Detected12": "the built-in check of 15 stated words matches at the 12 found",
            "ownerRetry": "after AMBIGUOUS_LENGTH the owner confirms the 12-word reading on the same recovery",
            "fingerprintRetry": "after LENGTH_DIFFERS the fingerprint confirms on the same recovery",
        }
        matches = {}
        for name, marker in expected.items():
            found = [
                {"line": number, "text": line}
                for number, line in enumerate(remote, 1)
                if marker in line
            ]
            assert len(found) == 4, (name, len(found))
            assert all("ok" in item["text"] for item in found)
            matches[name] = found
        modes = [
            {"line": number, "text": line}
            for number, line in enumerate(remote, 1)
            if any(
                marker in line
                for marker in (
                    "chromium 156.0.8078.4, standard mode:",
                    "chromium 156.0.8078.4, fast mode:",
                    "firefox 157.0, standard mode:",
                    "firefox 157.0, fast mode:",
                )
            )
        ]
        assert len(modes) == 4
        host = self.root.parent / "multi-chain-wallet-tools"
        host_paths = [
            item.removeprefix("../multi-chain-wallet-tools/")
            for item in paths
            if item.startswith("../multi-chain-wallet-tools/")
            and not item.endswith("AGENTS.md")
        ]
        spec = self.root.parent / "mhfe_spec"
        tag_readme = self.git(spec, "show", "v0.6.0:README.md")
        current_readme = (spec / "README.md").read_text()
        start = 'The built-in check\n  follows the length rules'
        # The paragraph's normative requirement is unchanged at the published specification tag.
        end = 'reports "not verified".'
        paragraphs = []
        for text in (tag_readme, current_readme):
            beginning = text.index(start)
            ending = text.index(end, beginning) + len(end)
            paragraphs.append(text[beginning:ending])
        assert paragraphs[0] == paragraphs[1]
        result = {
            "auditId": "AUD-019",
            "capturedUtc": datetime.now(timezone.utc).isoformat(),
            "method": "Read source and retained command logs; no product execution, KDF, build or new browser run.",
            "mhfeHead": self.git(self.root, "rev-parse", "HEAD"),
            "specHead": self.git(spec, "rev-parse", "HEAD"),
            "specTagCommit": self.git(spec, "rev-parse", "v0.6.0^{commit}"),
            "specNormativeParagraphMatchesPublishedTag": True,
            "hostHead": self.git(host, "rev-parse", "HEAD"),
            "hostScopedStatus": self.git(host, "status", "--short", "--", *host_paths).splitlines(),
            "sources": [self.bind(path) for path in paths],
            "evidence": [self.bind(path) for path in evidence_paths],
            "currentRemoteModes": modes,
            "currentRemoteAssertions": matches,
            "limits": [
                "Retained CI logs are source-bound shared evidence, not a new execution by this reviewer.",
                "The remote browser worker runs real WASM with the documented reduced-cost C Argon2 wrapper.",
                "The additional eight retry cases use stand-ins and do not replace the shared actual-WASM proof.",
                "Foreign host modules are dirty source, not a clean signed host revision or a full host acceptance run.",
            ],
        }
        target = self.evidence / "native-skeptic-source-bindings.json"
        with target.open("x") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
        print(
            json.dumps(
                {
                    "sources": len(paths),
                    "sharedEvidenceFiles": len(evidence_paths),
                    "modes": len(modes),
                    "observedAssertions": sum(len(items) for items in matches.values()),
                    "output": str(target.relative_to(self.root)),
                    "sha256": self.digest(target.read_bytes()),
                }
            )
        )


if __name__ == "__main__":
    SkepticBindings().execute()
