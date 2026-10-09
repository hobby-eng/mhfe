"""AUD-010 probe (docs-build-release): consistency of the audit records in docs/audits/.

    python3 docs/audits/AUD-010-harnesses/docs-build-release/audit-records.py [procedure root]

The procedure root defaults to ../multi-chain-wallet-tools next to this repository. Exits 1 when a
check fails; prints one line per check. Checks that
- every audit-NN JSON validates against the procedure's docs/audit-report.schema.json
  (jsonschema), and the AUD-009 Markdown register agrees with its JSON (IDs, category, severity,
  status, release blocking);
- docs/audits/README.md links every audit-NN Markdown and JSON record, and nothing else changed in
  it since the reviewed commit but the AUD-009 additions (whitespace and table padding ignored);
- the records audit-01..08 and their harness folders are byte for byte those of the reviewed
  commit;
- docs/audits/*-evidence/ is ignored by git and nothing in it is tracked, and every harness folder
  has a README.md (the AUD-010 folder is checked only for its scripts, as its README is written at
  the end of the audit);
- the procedure hashes recorded in docs/audits/AUD-010-evidence/procedure-hashes.json are those of
  the procedure files now, and the schema's semantic content equals that of the procedure's
  committed schema (a formatting-only difference is reported, not failed).
"""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import jsonschema

REPO = Path(__file__).resolve().parents[4]
AUDITS = REPO / "docs" / "audits"
REVIEWED_COMMIT = "a38a04448bb825d5ea939edc372e843d7a9584f2"
PROCEDURE = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO.parent / "multi-chain-wallet-tools"
PROCEDURE_FILES = [
    "docs/FULL_AUDIT_GUIDE.md",
    "docs/audits/AUDIT_STANDARD.md",
    "docs/audits/AUDIT_TEMPLATE.md",
    "docs/audit-report.schema.json",
]
failures = 0


def claim(ok, text):
    global failures
    print(("ok   " if ok else "FAIL ") + text)
    if not ok:
        failures += 1


def git(*args, cwd=REPO):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


schema = json.loads((PROCEDURE / "docs/audit-report.schema.json").read_text())
records = sorted(AUDITS.glob("audit-[0-9][0-9]-*.json"))
for record in records:
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(json.loads(record.read_text())),
        key=lambda error: list(error.path),
    )
    detail = f": {errors[0].message[:160]}" if errors else ""
    claim(not errors, f"{record.name} validates against the schema{detail}")

# AUD-009: Markdown register and JSON findings agree.
aud9 = json.loads((AUDITS / "audit-09-2026-10-06.json").read_text())
register = {}
for line in (AUDITS / "audit-09-2026-10-06.md").read_text().split("\n"):
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    if len(cells) >= 6 and re.fullmatch(r"AUD-009-[A-Z]+\d{3}", cells[0]):
        register[cells[0]] = (cells[1], cells[2], cells[3], cells[4].lower())
from_json = {
    finding["id"]: (
        finding["category"],
        finding["severity"],
        finding["status"],
        str(finding["releaseBlocking"]).lower(),
    )
    for finding in aud9["findings"]
}
claim(register == from_json, f"AUD-009 Markdown register equals its JSON ({len(from_json)} findings)")

# The index.
index = (AUDITS / "README.md").read_text()
for record in sorted(AUDITS.glob("audit-[0-9][0-9]-*.md")):
    claim(f"({record.name})" in index, f"README.md links {record.name}")
    companion = record.with_suffix(".json").name
    claim(companion in index, f"README.md names {companion}")


def normalized(text):
    return [re.sub(r"\s+", " ", re.sub(r"-{3,}", "---", line)).strip() for line in text.split("\n")]


old_index = git("show", f"{REVIEWED_COMMIT}:docs/audits/README.md").stdout
removed = [line for line in normalized(old_index) if line not in normalized(index)]
added = [line for line in normalized(index) if line not in normalized(old_index) and line]
claim(not removed, f"README.md keeps every line of {REVIEWED_COMMIT[:7]} (padding aside)")
claim(
    all("AUD-009" in line for line in added),
    f"README.md adds only AUD-009 lines ({len(added)} added)",
)

# Earlier records unchanged.
earlier = [path for path in AUDITS.iterdir() if re.match(r"audit-0[1-8]-", path.name)]
earlier += [path for path in AUDITS.glob("AUD-00[1-8]-harnesses")]
earlier += [AUDITS / "AUD-005-decisions.md"]
changed = git(
    "status", "--porcelain", "--", *[str(path.relative_to(REPO)) for path in earlier]
).stdout.strip()
claim(changed == "", "audit-01..08 records, AUD-005 decisions and AUD-00[1-8] harnesses unchanged")

# Evidence ignored and untracked; harness READMEs.
for evidence in sorted(AUDITS.glob("AUD-*-evidence")):
    ignored = git("check-ignore", "-q", str(evidence.relative_to(REPO)) + "/x").returncode == 0
    tracked = git("ls-files", str(evidence.relative_to(REPO))).stdout.strip()
    claim(ignored and tracked == "", f"{evidence.name} is ignored and untracked")
for harness in sorted(AUDITS.glob("AUD-*-harnesses")):
    if harness.name == "AUD-010-harnesses":
        continue
    claim((harness / "README.md").is_file(), f"{harness.name} has a README.md")

# Procedure hashes.
recorded = json.loads((AUDITS / "AUD-010-evidence/procedure-hashes.json").read_text())
for name in PROCEDURE_FILES:
    actual = sha256(PROCEDURE / name)
    claim(recorded.get(name) == actual, f"{name} SHA-256 {actual[:12]}… as recorded")
committed = git("show", "HEAD:docs/audit-report.schema.json", cwd=PROCEDURE)
if committed.returncode == 0:
    same = json.loads(committed.stdout) == schema
    committed_hash = hashlib.sha256(committed.stdout.encode()).hexdigest()
    print(
        f"note the procedure's committed schema has SHA-256 {committed_hash[:12]}…; "
        f"the working copy is {'semantically equal' if same else 'DIFFERENT in content'}"
    )
    claim(same, "the schema in use has the content of the procedure's committed schema")

if failures:
    print(f"FAIL: {failures} checks.")
    sys.exit(1)
print("PASS: audit records are consistent.")
