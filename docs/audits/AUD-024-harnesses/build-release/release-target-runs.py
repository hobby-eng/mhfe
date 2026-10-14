"""AUD-024 build-release harness: is every program a release ships run by some check?

    python3 docs/audits/AUD-024-harnesses/build-release/release-target-runs.py

Static review of the repository's release recipe and workflows. The shipped targets are read from
scripts/package-release.sh (its `cli_package <name> <triple>` lines; an empty triple is the
container's own x86_64-unknown-linux-gnu). The targets that some check runs are those of every
`cargo test` in packaging/Dockerfile.reproducible (the container's own target) and in the
workflows: a job's `cargo test` without --target runs on its runner's own target, taken from the
table RUNNER_HOSTS below (GitHub's ubuntu-24.04 and windows-2025 are x86-64 with the MSVC host
toolchain on Windows; macos-15 is Apple silicon). It fails (exit 1) when a shipped target is run by
no check, and lists it.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
CONTAINER = "x86_64-unknown-linux-gnu"
RUNNER_HOSTS = {
    "ubuntu-24.04": "x86_64-unknown-linux-gnu",
    "ubuntu-latest": "x86_64-unknown-linux-gnu",
    "windows-2025": "x86_64-pc-windows-msvc",
    "macos-15": "aarch64-apple-darwin",
}


def shipped():
    text = (ROOT / "scripts/package-release.sh").read_text()
    targets = {}
    for match in re.finditer(r'^\s*([\w-]+)\)\s*(?:\n\s*)?cli_package "\$package" (\S+)', text, re.M):
        name, triple = match.group(1), match.group(2)
        targets[name] = CONTAINER if triple == '""' else triple
    return targets


def run_by_checks():
    found = {}
    docker = (ROOT / "packaging/Dockerfile.reproducible").read_text()
    for line in docker.splitlines():
        if "cargo test" in line:
            found.setdefault(CONTAINER, []).append(f"Dockerfile.reproducible: {line.strip()}")
    for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
        text = workflow.read_text()
        # Each job: its runs-on value(s) and its cargo test lines.
        for job in re.split(r"\n  (?=[\w-]+:\n)", text.split("\njobs:\n", 1)[-1]):
            runners = re.findall(r"runs-on: (\S+)", job)
            matrix = re.findall(r"os: \[([^\]]*)\]", job)
            if runners == ["${{"] or (runners and runners[0].startswith("${{")):
                runners = [r.strip() for r in matrix[0].split(",")] if matrix else []
            for line in job.splitlines():
                if "cargo test" not in line:
                    continue
                target = re.search(r"--target (\S+)", line)
                for runner in runners:
                    triple = target.group(1) if target else RUNNER_HOSTS.get(runner, runner)
                    found.setdefault(triple, []).append(
                        f"{workflow.name} ({runner}): {line.strip()}")
    return found


def main():
    targets = shipped()
    runs = run_by_checks()
    failed = False
    for name, triple in sorted(targets.items()):
        where = runs.get(triple)
        if where:
            print(f"{name} ({triple}): run by {len(where)} check(s), e.g. {where[0]}")
        else:
            print(f"FAIL {name} ({triple}): no check runs a program built for this target")
            failed = True
    print("targets that checks run:", ", ".join(sorted(runs)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
