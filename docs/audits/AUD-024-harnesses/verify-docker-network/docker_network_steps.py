"""AUD-024 verifier probe: which RUN steps of the canonical Dockerfile at a commit have network.

Reads packaging/Dockerfile.reproducible and scripts/build-reproducible.sh from git (the commit
given as argv[1]), joins continuation lines, and prints each RUN with its stage, its first line
and whether it carries --network=none. Then it reports every RUN after the comment line that says
"No network from here on" that lacks --network=none, and whether the build script passes a
network option to docker buildx build. Exits 1 when such a RUN exists (the defect), 0 otherwise.
"""
import re
import subprocess
import sys

commit = sys.argv[1]


def show(path):
    return subprocess.run(["git", "show", f"{commit}:{path}"], check=True, capture_output=True,
                          text=True).stdout


lines = show("packaging/Dockerfile.reproducible").split("\n")
claim_line = next((i + 1 for i, line in enumerate(lines)
                   if line.startswith("#") and "No network from here on" in line), None)
print(f"comment 'No network from here on' at line {claim_line}")

stage = None
runs = []
i = 0
while i < len(lines):
    line = lines[i]
    start = i + 1
    text = line
    while text.rstrip().endswith("\\") and i + 1 < len(lines):
        i += 1
        text = text.rstrip()[:-1] + " " + lines[i].strip()
    i += 1
    if re.match(r"^FROM\s", text):
        match = re.search(r"\sAS\s+(\S+)", text, re.IGNORECASE)
        stage = match.group(1) if match else "?"
    elif re.match(r"^RUN\s", text):
        offline = re.match(r"^RUN\s+(--\S+\s+)*--network=none\b", text) is not None
        runs.append((start, i, stage, offline, text))

for start, end, stage_name, offline, text in runs:
    flag = "--network=none" if offline else "network: default"
    print(f"RUN lines {start}-{end} stage {stage_name}: {flag}: {text[:110]}")

after = [r for r in runs if claim_line is not None and r[0] > claim_line and not r[3]]
for start, end, stage_name, _, text in after:
    print(f"AFTER CLAIM, NOT --network=none: lines {start}-{end} (stage {stage_name})")

script = show("scripts/build-reproducible.sh")
network_option = re.search(r"--network\b", script)
print("build-reproducible.sh passes --network to docker:", bool(network_option))
sys.exit(1 if after else 0)
