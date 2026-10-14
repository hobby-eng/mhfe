#!/usr/bin/env python3
"""AUD-024, audit-records role: checks of the audit records in docs/audits/ (CHECK-DOC-003).

    python3 docs/audits/AUD-024-harnesses/audit-records/check_records.py [--schema PATH] [CHECK...]

Run from the repository root on commit b6fca69. Read-only: it reads the records, git objects and
the workspace procedure files, and writes nothing. Each check prints one line per problem and a
summary line; the script exits 1 when any selected check finds a problem, 0 otherwise. CHECK names:

  schema       every AUD-NNN-*.json validates against the workspace audit-report schema
  pairs        Markdown and JSON agree on own finding/observation IDs, register severities and
               statuses, and on remediation statuses where the Markdown says rows stay open
  dates        the date in a record's file name and JSON is its stated UTC completion date
  procedure    each procedure SHA-256 a record pins is the current file's, or procedure-changes.json
               gives the reverse edit that recovers it
  links        every relative Markdown link in docs/audits/ reaches a file tracked in git
  harnesses    every AUD-NNN-harnesses/README.md names its record's reviewed commit
  fixed-in     the files that AUD-023's remediation rows call "Fixed in" exist at the fix commit
  refuted      no candidate listed as refuted has a verdict that kept a defect (severity above info)

Needs python3 with jsonschema (schema check only) and git. --schema defaults to
../multi-chain-wallet-tools/docs/audit-report.schema.json, beside the repository.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

AUDITS = Path("docs/audits")
CATEGORIES = "SEC|FUN|API|BLD|DOC|UI|ARC"
WORKSPACE = Path("..").resolve()


def records():
    for md in sorted(AUDITS.glob("AUD-[0-9][0-9][0-9]-20*.md")):
        yield md, json.loads(md.with_suffix(".json").read_text(encoding="utf-8"))


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=False)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_schema(args):
    from jsonschema import Draft202012Validator

    schema = json.loads(Path(args.schema).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    problems = []
    for md, data in records():
        for error in validator.iter_errors(data):
            where = "/".join(map(str, error.absolute_path)) or "<root>"
            problems.append(f"{md.with_suffix('.json').name}: {where}: {error.message[:200]}")
    return problems


def table_after(lines, start):
    i = start
    while i < len(lines) and not lines[i].startswith("|"):
        i += 1
    if i >= len(lines):
        return [], []
    header = [cell.strip().lower() for cell in lines[i].strip().strip("|").split("|")]
    rows = []
    i += 2
    while i < len(lines) and lines[i].startswith("|"):
        rows.append([cell.strip() for cell in lines[i].strip().strip("|").split("|")])
        i += 1
    return header, rows


def check_pairs(args):
    problems = []
    for md, data in records():
        audit = data["auditId"]
        text = md.read_text(encoding="utf-8")
        lines = text.split("\n")
        own = re.compile(rf"\b{audit}-(?:{CATEGORIES})\d{{3}}\b")
        json_records = {r["id"]: r for key in ("findings", "observations") for r in data[key]}
        own_json = {i for i in json_records if own.fullmatch(i)}
        headed = {m.group(1) for m in re.finditer(rf"^#+\s+.*?({audit}-(?:{CATEGORIES})\d{{3}})\b", text, re.M)}
        register = {}
        for i, line in enumerate(lines):
            if re.match(r"^##+\s+Finding register", line):
                header, rows = table_after(lines, i + 1)
                for row in rows:
                    found = own.search(row[0])
                    if found:
                        register[found.group(0)] = dict(zip(header, row))
                break
        for missing in sorted(own_json - headed - set(register)):
            problems.append(f"{md.name}: {missing} ({json_records[missing]['kind']}, status "
                            f"{json_records[missing]['status']}) is in the JSON only")
        for missing in sorted((headed | set(register)) - own_json):
            problems.append(f"{md.name}: {missing} is in the Markdown only")
        for record_id, row in register.items():
            if record_id not in json_records:
                continue
            for column, key in (("severity", "severity"), ("status", "status")):
                cell = next((v for k, v in row.items() if column in k), None)
                value = json_records[record_id].get(key)
                if cell is not None and cell.strip("` ").lower() != str(value).lower():
                    problems.append(f"{md.name}: {record_id} register {column} {cell!r}, JSON {value!r}")
        if re.search(r"stays? open (here )?until a commit records", text):
            for entry in data.get("remediation", []):
                if own.fullmatch(entry["id"]) and entry["status"] in ("fixed", "verified") and not entry.get("fixCommit"):
                    problems.append(f"{md.name}: the Markdown says each row stays open until a commit "
                                    f"records it; JSON remediation {entry['id']} is {entry['status']!r} "
                                    f"with no fix commit")
    return problems


def check_dates(args):
    problems = []
    for md, data in records():
        named = re.search(r"(\d{4}-\d{2}-\d{2})\.md$", md.name).group(1)
        text = md.read_text(encoding="utf-8")
        stated = re.search(r"\*\*Completed \(UTC\):\*\*\s*(\d{4}-\d{2}-\d{2})", text)
        completed = (data.get("completedUtc") or "")[:10] or (stated.group(1) if stated else None)
        if completed and completed != named:
            problems.append(f"{md.name}: completed {completed} (UTC), file name and JSON date {named}/{data['date']}")
    return problems


def check_procedure(args):
    files = {
        "FULL_AUDIT_GUIDE.md": "multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md",
        "AUDIT_STANDARD.md": "multi-chain-wallet-tools/docs/audits/AUDIT_STANDARD.md",
        "AUDIT_TEMPLATE.md": "multi-chain-wallet-tools/docs/audits/AUDIT_TEMPLATE.md",
        "audit-report.schema.json": "multi-chain-wallet-tools/docs/audit-report.schema.json",
    }
    changes = json.loads((AUDITS / "procedure-changes.json").read_text(encoding="utf-8"))["changes"]
    recoverable = {(c["file"], c["auditedSha256"]) for c in changes}
    pins = {}
    for md, _ in records():
        text = md.read_text(encoding="utf-8")
        for short in files:
            for m in re.finditer(re.escape(short) + r"[^0-9a-f\n]{0,80}?([0-9a-f]{64})", text):
                pins.setdefault((short, m.group(1)), set()).add(md.name[:7])
    problems = []
    for (short, pinned), audits in sorted(pins.items()):
        path = WORKSPACE / files[short]
        current = sha256(path)
        if pinned != current and (files[short], pinned) not in recoverable:
            problems.append(f"{files[short]}: pinned {pinned[:16]} by {', '.join(sorted(audits))}; "
                            f"current {current[:16]}; no reverse edit in procedure-changes.json")
    return problems


def check_links(args):
    tracked = set(git("ls-files").stdout.split())
    directories = {str(Path(t).parent) for t in tracked}
    for t in list(directories):
        while t not in ("", "."):
            directories.add(t)
            t = str(Path(t).parent)
    problems = []
    for f in sorted(t for t in tracked if t.startswith("docs/audits/") and t.endswith(".md")):
        # Code blocks hold no links; they are blanked line for line so that line numbers stay right.
        text = re.sub(r"```.*?```", lambda block: "\n" * block.group(0).count("\n"),
                      Path(f).read_text(encoding="utf-8"), flags=re.S)
        for number, line in enumerate(text.split("\n"), 1):
            for m in re.finditer(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)", re.sub(r"`[^`]*`", "", line)):
                target = m.group(1).split("#")[0]
                if not target or re.match(r"^[a-z]+:", target):
                    continue
                resolved = os.path.normpath(os.path.join(os.path.dirname(f), target))
                if resolved in tracked or resolved in directories:
                    continue
                if re.search(r"AUD-\d{3}-evidence(/|$)", resolved) and "local-only" in text:
                    continue  # the record's own evidence folder, which it labels local-only (AUD-016)
                where = "outside the repository" if resolved.startswith("..") else (
                    "not tracked, present locally" if os.path.exists(resolved) else "missing")
                problems.append(f"{f}:{number}: {m.group(1)}: {where}")
    return problems


def check_harnesses(args):
    problems = []
    for md, data in records():
        readme = AUDITS / f"{data['auditId']}-harnesses" / "README.md"
        commit = (data.get("snapshot") or {}).get("commit")
        if not readme.is_file():
            continue
        named = set(re.findall(r"\b[0-9a-f]{7,40}\b", readme.read_text(encoding="utf-8")))
        if commit and not any(commit.startswith(h) for h in named):
            problems.append(f"{readme}: does not name the reviewed commit {commit[:12]}")
    return problems


def check_fixed_in(args):
    data = json.loads((AUDITS / "AUD-023-2026-10-13.json").read_text(encoding="utf-8"))
    problems = []
    for row in data["remediation"]:
        m = re.match(r"Fixed in (.*?)\.( Its own| Commit|$)", row["evidence"])
        if not m:
            continue
        fix = row["fixCommit"].split(",")[0].strip("` ")
        absent = [f.strip() for f in m.group(1).split(",")
                  if git("cat-file", "-e", f"{fix}:{f.strip()}").returncode != 0]
        if absent:
            problems.append(f"{row['id']}: fix commit {fix[:7]} has no {', '.join(absent)}")
    return problems


def check_refuted(args):
    problems = []
    for md, data in records():
        for candidate in data.get("refutedCandidates", []):
            for verdict in candidate.get("verdicts", []):
                if verdict.get("adjustedSeverity") not in (None, "info"):
                    problems.append(f"{md.name}: refuted candidate {candidate['title'][:70]!r}: verdict "
                                    f"reproduced={verdict.get('reproduced')}, adjusted severity "
                                    f"{verdict['adjustedSeverity']}, in no finding")
    return problems


CHECKS = {"schema": check_schema, "pairs": check_pairs, "dates": check_dates,
          "procedure": check_procedure, "links": check_links, "harnesses": check_harnesses,
          "fixed-in": check_fixed_in, "refuted": check_refuted}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--schema", default=str(WORKSPACE / "multi-chain-wallet-tools/docs/audit-report.schema.json"))
    parser.add_argument("checks", nargs="*", metavar="CHECK", help=", ".join(CHECKS))
    args = parser.parse_args()
    unknown = [name for name in args.checks if name not in CHECKS]
    if unknown:
        parser.error(f"unknown check(s): {', '.join(unknown)}; the checks are {', '.join(CHECKS)}")
    args.checks = args.checks or list(CHECKS)
    failed = 0
    for name in args.checks:
        problems = CHECKS[name](args)
        for problem in problems:
            print(f"  {name}: {problem}")
        print(f"{name}: {'FAIL' if problems else 'ok'} ({len(problems)} problem(s))")
        failed += bool(problems)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
