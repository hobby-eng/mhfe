#!/usr/bin/env python3
"""Validate the separate AUD-008 remediation phase without rewriting its baseline."""

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess

import jsonschema

ROOT = Path(__file__).resolve().parents[3]
AUDITS = ROOT / "docs/audits"
EVIDENCE = AUDITS / "AUD-008-evidence"
STEM = "audit-08-2026-10-06"
BASELINE_HASHES = {
    "json": "a164482e52d9e1ef38febf8d01d82e054fd7e863ffaa501c702aa8dc86f96470",
    "markdown": "c89fc343948413c2114c533a0c92cd57e7e3b5f0f2fcea36dc319f148378d13f",
}
HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
FINDING_HEADING = re.compile(r"^#### (AUD-008-[A-Z]{2,3}[0-9]{3}) — (.+)$", re.M)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError(f"Non-finite JSON number: {value}")


def read(path):
    return json.loads(
        path.read_text(), object_pairs_hook=unique_pairs, parse_constant=invalid_constant
    )


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo).decode().strip()


def ancestor(repo, older, newer):
    return subprocess.run(
        ["git", "merge-base", "--is-ancestor", older, newer], cwd=repo
    ).returncode == 0


def relative_file(directory, name):
    require(isinstance(name, str), "A file path must be a string")
    path = directory / name
    require(not Path(name).is_absolute(), f"Expected a relative path: {name}")
    require(path.resolve().is_relative_to(directory.resolve()), f"Escaping path: {name}")
    require(path.is_file(), f"Missing retained file: {path}")
    return path


def verify_hashes(directory, manifest):
    require(isinstance(manifest, dict) and manifest, "Empty hash manifest")
    for name, expected in manifest.items():
        require(bool(HASH_PATTERN.fullmatch(expected)), f"Invalid SHA-256: {name}")
        require(digest(relative_file(directory, name)) == expected, f"Hash mismatch: {name}")


def source_manifest(repo):
    paths = git(repo, "ls-files", "-z").split("\0")
    return {
        name: digest(repo / name)
        for name in sorted(paths)
        if name and not name.startswith("docs/audits/") and (repo / name).is_file()
    }


def fingerprint(files):
    encoded = "".join(name + "\0" + files[name] + "\n" for name in sorted(files))
    return hashlib.sha256(encoded.encode()).hexdigest()


def verify_snapshot(repo, captured):
    current = source_manifest(repo)
    require(current == captured["files"], f"Current product manifest differs: {repo.name}")
    require(fingerprint(current) == captured["sourceFingerprint"], "Source fingerprint differs")
    head = git(repo, "rev-parse", "HEAD")
    require(ancestor(repo, captured["commit"], head), f"Snapshot is not an ancestor: {repo.name}")
    return {"commit": head, "fileCount": len(current), "sourceFingerprint": fingerprint(current)}


def signed_ancestor(commit, head):
    resolved = git(ROOT, "rev-parse", commit + "^{commit}")
    require(resolved == commit, f"A full fix/verification commit is required: {commit}")
    require(ancestor(ROOT, commit, head), f"Fix/verification commit is not an ancestor: {commit}")
    header = git(ROOT, "cat-file", "-p", commit).split("\n\n", 1)[0]
    require(
        any(line.startswith("gpgsig ") for line in header.splitlines()),
        f"Unsigned commit: {commit}",
    )


def verify_historical_record(record, baseline):
    mutable = {"findings", "remediation", "assessment", "limitations"}
    require(set(record) == set(baseline) | {"remediationVerification"}, "Unexpected report fields")
    for key, value in baseline.items():
        if key not in mutable:
            require(record[key] == value, f"Historical field changed: {key}")
    require(
        record["limitations"][: len(baseline["limitations"])] == baseline["limitations"],
        "Historical limitations changed",
    )
    require(
        record["assessment"]["releaseReady"] is False,
        "Targeted remediation is not release approval",
    )
    require(
        record["assessment"]["verdict"] == "NO_OPEN_FINDINGS",
        "Current finding assessment differs",
    )
    old = {item["id"]: item for item in baseline["findings"]}
    current = {item["id"]: item for item in record["findings"]}
    require(
        len(current) == len(record["findings"]) and set(current) == set(old),
        "Finding IDs changed",
    )
    for finding_id, item in current.items():
        require(item["status"] == "verified", f"Finding is not verified: {finding_id}")
        require(
            item["originalStatus"] == old[finding_id]["status"],
            f"Missing original status: {finding_id}",
        )
        retained = {
            key: value for key, value in item.items() if key not in {"status", "originalStatus"}
        }
        expected = {key: value for key, value in old[finding_id].items() if key != "status"}
        require(retained == expected, f"Substantive historical finding changed: {finding_id}")
    return current


def verify_original_evidence(baseline, phase):
    required = {"snapshot.json", "procedure-hashes.json", "report-validation.json"}
    require(
        required <= set(phase["originalEvidenceHashes"]),
        "Original evidence manifest omits required records",
    )
    verify_hashes(EVIDENCE, phase["originalEvidenceHashes"])
    original_snapshot = read(EVIDENCE / "snapshot.json")
    for name, commit_key, hash_key in (
        ("mhfe", "commit", "sourceFingerprint"),
        ("specification", "specificationCommit", "specificationSourceFingerprint"),
    ):
        captured = original_snapshot[name]
        require(
            captured["commit"] == baseline["snapshot"][commit_key]
            and captured["sourceFingerprint"] == baseline["snapshot"][hash_key]
            and fingerprint(captured["files"]) == captured["sourceFingerprint"],
            f"Original source snapshot differs: {name}",
        )
    original_validation = read(EVIDENCE / "report-validation.json")
    require(
        original_validation["jsonSha256"] == BASELINE_HASHES["json"]
        and original_validation["markdownSha256"] == BASELINE_HASHES["markdown"],
        "Original validation does not bind the retained baseline reports",
    )
    require(
        read(EVIDENCE / "procedure-hashes.json") == baseline["procedureHashes"],
        "Original procedure binding changed",
    )
    for reviewer in baseline["reviewerPhases"]:
        path = relative_file(EVIDENCE, reviewer["localEvidence"])
        require(
            digest(path) == reviewer["sha256"],
            f"Original reviewer evidence changed: {path.name}",
        )
    final_skeptic = baseline["finalSkepticReview"]
    require(
        digest(relative_file(EVIDENCE, final_skeptic["localEvidence"])) == final_skeptic["sha256"],
        "Original final-skeptic evidence changed",
    )
    original_wallet = read(EVIDENCE / "wallet-review.json")["evidence"]
    for entry in baseline["executedCommands"]:
        ledger_path = relative_file(EVIDENCE, entry["localLedger"])
        ledger = read(ledger_path)
        expected_ledger = {key: value for key, value in entry.items() if key != "localLedger"}
        # The baseline report annotates incomplete ledgers and normalizes their log hash;
        # these additions were not written into the preserved original ledger files.
        if "metadataLimit" in expected_ledger:
            require("logSha256" not in ledger, "Unexpected original normalized ledger")
            del expected_ledger["metadataLimit"]
            del expected_ledger["logSha256"]
        elif "logSHA256" in ledger and "logSha256" not in ledger:
            require(
                expected_ledger.pop("logSha256") == ledger["logSHA256"],
                "Normalized original hash differs",
            )
        require(
            ledger == expected_ledger,
            f"Original command ledger changed: {ledger_path.name}",
        )
        log = ledger_path.name.removesuffix(".command.json") + ".log"
        expected = ledger.get("logSha256", ledger.get("logSHA256", ledger.get("log_sha256")))
        if expected is None:
            require(
                original_wallet[ledger_path.name] == digest(ledger_path),
                "Incomplete original ledger changed",
            )
            expected = original_wallet[log]
        require(
            digest(relative_file(EVIDENCE, log)) == expected,
            f"Original command output changed: {log}",
        )


def verify_commands(phase):
    entries = phase["commands"]
    require(isinstance(entries, list) and entries, "No successful remediation checks recorded")
    commands = {}
    for entry in entries:
        name = entry["localLedger"]
        require(
            name not in commands and name.endswith(".command.json"),
            f"Duplicate or invalid ledger: {name}",
        )
        actual = read(relative_file(EVIDENCE, name))
        expected = {
            key: value for key, value in entry.items() if key not in {"localLedger", "label"}
        }
        require(actual == expected, f"Remediation command ledger mismatch: {name}")
        require(
            actual["exitCode"] == 0 and not actual.get("timedOut", False),
            f"Check did not pass: {name}",
        )
        require(actual["cwd"] == str(ROOT), f"Unexpected command working directory: {name}")
        require(
            actual["startedAt"] and actual["finishedAt"] and actual["argv"],
            f"Incomplete ledger: {name}",
        )
        log = relative_file(EVIDENCE, name.removesuffix(".command.json") + ".log")
        require(
            digest(log) == actual["logSha256"],
            f"Remediation command output changed: {log.name}",
        )
        require(
            log.stat().st_size == actual["logBytes"],
            f"Remediation output size differs: {log.name}",
        )
        commands[name] = entry
    return commands


def finding_sections(markdown):
    sections = {}
    for match in FINDING_HEADING.finditer(markdown):
        require(match[1] not in sections, f"Duplicate Markdown finding: {match[1]}")
        following = re.search(r"^#{1,4} ", markdown[match.end():], re.M)
        end = match.end() + following.start() if following else len(markdown)
        sections[match[1]] = (match[2], markdown[match.end():end])
    return sections


def verify_markdown(markdown, old_markdown, findings, remediations, phase):
    current = finding_sections(markdown)
    old = finding_sections(old_markdown)
    require(set(current) == set(findings) == set(old), "Markdown finding IDs differ")
    for finding_id, finding in findings.items():
        heading, body = current[finding_id]
        expected_heading = f'{finding["severity"].capitalize()} — {finding["title"]}'
        require(
            heading == old[finding_id][0] == expected_heading,
            f"Markdown finding heading changed: {finding_id}",
        )
        require("**Status:** verified" in body, f"Markdown current status differs: {finding_id}")
        require(
            re.search(r"\*\*Original status:\*\* open", body),
            f"Markdown original status missing: {finding_id}",
        )
        # Status lines may change; every original substantive line must remain in order.
        retained = [
            line for line in old[finding_id][1].splitlines()
            if line.strip() and "**Category:**" not in line
        ]
        cursor = 0
        for line in retained:
            index = body.find(line, cursor)
            require(index >= 0, f"Historical Markdown finding prose changed: {finding_id}")
            cursor = index + len(line)
        rows = [line for line in markdown.splitlines() if line.startswith("| " + finding_id + " |")]
        require(len(rows) == 2, f"Expected finding-register and remediation rows: {finding_id}")
        cells = [[value.strip() for value in row.split("|")[1:-1]] for row in rows]
        register = [row for row in cells if len(row) == 7]
        repairs = [row for row in cells if len(row) == 5]
        require(len(register) == len(repairs) == 1, f"Markdown table shape differs: {finding_id}")
        require(
            register[0][1:4] == [finding["category"], finding["kind"], finding["severity"]]
            and register[0][5].lower() == str(finding["releaseBlocking"]).lower()
            and register[0][6] == finding["title"],
            f"Markdown finding register differs: {finding_id}",
        )
        require(
            register[0][4] == repairs[0][1] == "verified",
            f"Markdown table status differs: {finding_id}",
        )
        item = remediations[finding_id]
        for column, key in ((2, "fixCommit"), (3, "verificationCommit")):
            if item[key] is not None:
                require(
                    item[key][:7] in repairs[0][column],
                    f"Markdown commit differs: {finding_id}",
                )
        require(
            any(name in repairs[0][4] for name in item["verificationCommands"]),
            f"Markdown remediation lacks scoped evidence: {finding_id}",
        )
    require(
        phase["snapshot"]["sourceFingerprint"] in markdown,
        "Remediation fingerprint missing in Markdown",
    )
    require(
        phase["snapshot"]["commit"] in markdown,
        "Remediation snapshot commit missing in Markdown",
    )
    require(not re.search(r"[\u0400-\u04ff]", markdown), "Report must remain English")


def validate(record, markdown):
    schema = read(ROOT.parent / "multi-chain-wallet-tools/docs/audit-report.schema.json")
    jsonschema.Draft202012Validator(schema).validate(record)
    baseline_paths = {
        "json": EVIDENCE / "remediation-baseline-report.json",
        "markdown": EVIDENCE / "remediation-baseline-report.md",
    }
    for kind, path in baseline_paths.items():
        require(digest(path) == BASELINE_HASHES[kind], f"Original baseline report changed: {kind}")
    baseline = read(baseline_paths["json"])
    phase = record["remediationVerification"]
    require(phase["originalReportHashes"] == BASELINE_HASHES, "Incorrect original report hashes")
    findings = verify_historical_record(record, baseline)
    verify_original_evidence(baseline, phase)
    require(
        read(EVIDENCE / "remediation-snapshot.json") == phase["snapshot"],
        "Retained remediation snapshot differs",
    )
    snapshots = {"mhfe": verify_snapshot(ROOT, phase["snapshot"])}
    snapshots["specification"] = verify_snapshot(
        ROOT.parent / "mhfe_spec", phase["snapshot"]["specification"]
    )
    require(
        ancestor(ROOT, baseline["snapshot"]["commit"], phase["snapshot"]["commit"]),
        "Reviewed base is not an ancestor",
    )
    require(
        ancestor(
            ROOT.parent / "mhfe_spec",
            baseline["snapshot"]["specificationCommit"],
            phase["snapshot"]["specification"]["commit"],
        ),
        "Specification base is not an ancestor",
    )
    for name, expected in phase["procedureHashes"].items():
        require(Path(name).is_absolute(), f"Expected absolute procedure path: {name}")
        require(digest(Path(name)) == expected, f"Current procedure hash differs: {name}")
    require(
        set(phase["procedureHashes"]) == set(baseline["procedureHashes"]),
        "Procedure file set changed",
    )
    verify_hashes(ROOT, phase["harnessHashes"])
    require(
        "docs/audits/AUD-008-harnesses/remediation-validate.py" in phase["harnessHashes"],
        "Validator is not hash-bound",
    )
    commands = verify_commands(phase)
    remediations = {item["id"]: item for item in record["remediation"]}
    require(
        len(remediations) == len(record["remediation"]) and set(remediations) == set(findings),
        "Remediation IDs differ",
    )
    for finding_id, item in remediations.items():
        require(
            item["status"] == "verified" and item["originalStatus"] == "open",
            f"Invalid remediation status: {finding_id}",
        )
        require(
            item["sourceFingerprint"] == phase["snapshot"]["sourceFingerprint"],
            f"Unbound remediation source: {finding_id}",
        )
        require(item["evidence"], f"Missing remediation evidence: {finding_id}")
        checks = item["verificationCommands"]
        require(
            checks and len(checks) == len(set(checks)) and set(checks) <= set(commands),
            f"Remediation lacks passing scoped checks: {finding_id}",
        )
        for key in ("fixCommit", "verificationCommit"):
            if item[key] is not None:
                signed_ancestor(item[key], snapshots["mhfe"]["commit"])
    counts = dict(Counter(item["status"] for item in findings.values()))
    counts.setdefault("open", 0)
    require(phase["statusCounts"] == counts, "Remediation status counts differ")
    verify_markdown(markdown, baseline_paths["markdown"].read_text(), findings, remediations, phase)
    for doc in (AUDITS / (STEM + ".md"), AUDITS / "AUD-008-harnesses/README.md"):
        for target in re.findall(r"\]\(([^)]+)\)", doc.read_text()):
            if not target.startswith(("https://", "http://", "#")):
                require(
                    (doc.parent / target.split("#", 1)[0]).exists(),
                    f"Missing linked file: {target}",
                )
    staged = git(ROOT, "diff", "--cached", "--name-only").splitlines()
    require(not any("AUD-008-evidence/" in name for name in staged), "Local evidence is staged")
    ignored = subprocess.run(
        ["git", "check-ignore", "-q", "docs/audits/AUD-008-evidence/remediation-snapshot.json"],
        cwd=ROOT,
    ).returncode == 0
    require(ignored, "Remediation evidence is not ignored")
    require(
        f"[AUD-008]({STEM}.md)" in (AUDITS / "README.md").read_text(),
        "Audit index entry missing",
    )
    require(phase["limitations"], "Targeted verification limitations must be explicit")
    return {
        "auditId": "AUD-008",
        "phase": "remediation",
        "passed": True,
        "schema": "Draft202012",
        "statusCounts": counts,
        "checkedSuccessfulCommandLogs": len(commands),
        "snapshots": snapshots,
        "historicalRecordAndEvidencePreserved": True,
        "evidenceIgnoredAndUnstaged": True,
        "signatureCheck": "Signed ancestor headers are present; signer trust is not established.",
    }


def main():
    json_path = AUDITS / (STEM + ".json")
    markdown_path = AUDITS / (STEM + ".md")
    result = validate(read(json_path), markdown_path.read_text())
    result.update(jsonSha256=digest(json_path), markdownSha256=digest(markdown_path))
    target = EVIDENCE / "remediation-report-validation.json"
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
