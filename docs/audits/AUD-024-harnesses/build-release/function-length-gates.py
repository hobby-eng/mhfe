"""AUD-024 build-release harness: do the repository's function-length gates stop where the coding
guide says?

    python3 docs/audits/AUD-024-harnesses/build-release/function-length-gates.py [GUIDE_DIR]

GUIDE_DIR is the workspace's .github/instructions (default: two levels above the repository). The
value is read from RUST-01 in code-rust.instructions.md ("too-many-lines-threshold = N") and from
CORE-15 in code-core.instructions.md ("max-lines-per-function N in .oxlintrc.json"), and compared
with clippy.toml and .oxlintrc.json of the checkout. It also lists the comments of clippy.toml and
Cargo.toml that state a limit for CORE-15. It fails (exit 1) on any difference.
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]


def main(arguments):
    guide = pathlib.Path(arguments[0]) if arguments else ROOT.parent / ".github" / "instructions"
    rust = (guide / "code-rust.instructions.md").read_text()
    core = (guide / "code-core.instructions.md").read_text()
    clippy_rule = int(re.search(r"too-many-lines-threshold = (\d+)", rust).group(1))
    lint_rule = int(re.search(r"max-lines-per-function` (\d+) in `\.oxlintrc\.json`", core).group(1))
    clippy = int(re.search(r"^too-many-lines-threshold = (\d+)", (ROOT / "clippy.toml").read_text(),
                           re.M).group(1))
    oxlint = json.loads((ROOT / ".oxlintrc.json").read_text())
    lint = oxlint["rules"]["max-lines-per-function"][1]["max"]
    print(f"guide RUST-01 clippy threshold {clippy_rule}; clippy.toml {clippy}")
    print(f"guide CORE-15 lint max-lines-per-function {lint_rule}; .oxlintrc.json {lint}")
    for name in ("clippy.toml", "Cargo.toml"):
        for number, line in enumerate((ROOT / name).read_text().splitlines(), 1):
            if "CORE-15" in line:
                print(f"{name}:{number}: {line.strip()}")
    failed = clippy != clippy_rule or lint != lint_rule
    if failed:
        print("FAIL: the gates stop at another function length than the guide's")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
