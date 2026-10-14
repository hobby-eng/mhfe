"""AUD-024 build-release harness: do the provenance gates that take seconds run on a push or a
pull request?

    python3 docs/audits/AUD-024-harnesses/build-release/fast-gate-coverage.py

CI runs scripts/check-fast.sh on a push and a pull request and scripts/check.sh only for a release
tag or by hand (.github/workflows/ci.yml, RELEASE_CHECKS). This lists, for each provenance gate of
scripts/check.sh, whether check-fast.sh runs it, and shows the crate versions of Cargo.lock that
THIRD_PARTY_NOTICES.md's generated part repeats, which a dependency update changes. It fails
(exit 1) when a gate of PROVENANCE_GATES runs only in check.sh.
"""

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[4]
PROVENANCE_GATES = (
    "scripts/third-party-licenses.py --check",
    "scripts/verify-vendored-argon2.mjs",
)


def main():
    fast = (ROOT / "scripts/check-fast.sh").read_text()
    full = (ROOT / "scripts/check.sh").read_text()
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    print("ci.yml push/pull_request step:",
          re.search(r"- name: Run the fast checks\n(.*\n){2}", ci).group(0).strip().replace("\n", " | "))
    failed = False
    for gate in PROVENANCE_GATES:
        in_fast, in_full = gate in fast, gate in full
        print(f"{gate}: check-fast.sh {in_fast}, check.sh {in_full}")
        if in_full and not in_fast:
            failed = True
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
    generated = notices[notices.index("## Rust crates"):]
    repeated = [f"{p['name']} {p['version']}" for p in lock["package"]
                if f"- `{p['name']}` {p['version']}:" in generated]
    print(f"crate versions of Cargo.lock repeated in the generated notices: {len(repeated)}, "
          f"e.g. {', '.join(repeated[:4])}")
    if failed:
        print("FAIL: a provenance gate runs only for a release tag or by hand")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
