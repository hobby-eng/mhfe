#!/usr/bin/env python3
# TOOL-01: independent JSON/Markdown evidence checker beside the Node
# documentation gates.
"""
Validate current audit records, including documentation-only amendments.

python3 scripts/verify-audit-records.py [--self-test | --schema |
--metadata-only]

Reuses AUD-024's retained schema/pair/date/commit checks without
rewriting
that historical harness. The live inventory includes pending renames and
new, nonignored records. Procedure recovery verifies bytes through every
reverse edit, then checks every pin, including pins absent from the
list.
Retained Python harnesses are parsed without executing their historical
checks or report generators.
The optional schema check needs jsonschema, as the retained harness
does.
--metadata-only checks a standalone, possibly shallow checkout without
sibling procedure files or historical Git objects.
"""
import argparse
import ast
import hashlib
import json
import os
import re
import runpy
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUDITS = ROOT / "docs/audits"
WORKSPACE = ROOT.parent
BASELINE = AUDITS / "AUD-024-harnesses/audit-records/check_records.py"
PROCEDURES = {
    "FULL_AUDIT_GUIDE.md": "multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md",
    "AUDIT_STANDARD.md": "multi-chain-wallet-tools/docs/audits/AUDIT_STANDARD.md",
    "AUDIT_TEMPLATE.md": "multi-chain-wallet-tools/docs/audits/AUDIT_TEMPLATE.md",
    "audit-report.schema.json": "multi-chain-wallet-tools/docs/audit-report.schema.json",
}


def sha256(data):
    """SHA-256 of exact bytes, without newline or JSON normalization."""
    return hashlib.sha256(data).hexdigest()


def recover_versions(current, changes, historical):
    """Recover every listed predecessor; reject incomplete or incorrect
    edges.
    """
    versions = {sha256(current): current}
    pending = list(changes)
    while pending:
        progress = False
        for change in pending[:]:
            source = versions.get(change["currentSha256"])
            if source is None:
                continue
            if "reverseEdit" in change:
                edit = change["reverseEdit"]
                text = source.decode("utf-8")
                if text.count(edit["current"]) != 1:
                    raise ValueError("reverse edit does not match exactly once")
                previous = text.replace(edit["current"], edit["audited"], 1).encode()
            else:
                previous = historical(change)
                if json.loads(previous) != json.loads(source):
                    raise ValueError("historical schema is not a formatting-only change")
            if sha256(previous) != change["auditedSha256"]:
                raise ValueError("recovered predecessor has the wrong SHA-256")
            versions[sha256(previous)] = previous
            pending.remove(change)
            progress = True
        if not progress:
            raise ValueError("listed current hash cannot be reached from the current file")
    return versions


def historical_schema(change):
    """A schema predecessor reachable on the sibling repository's main
    branch.
    """
    repo = WORKSPACE / "multi-chain-wallet-tools"
    commit = change["auditedGitCommit"]
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, "main"], cwd=repo, check=True)
    return subprocess.check_output([
        "git", "show", f"{commit}:{change['auditedGitPath']}",
    ], cwd=repo)


def procedure_findings(records):
    """Every pin must be reachable, not merely named in a list of edits.
    """
    changes = json.loads((AUDITS / "procedure-changes.json").read_text())["changes"]
    found = []
    for name, relative in PROCEDURES.items():
        try:
            versions = recover_versions(
                (WORKSPACE / relative).read_bytes(),
                [change for change in changes if change["file"] == relative], historical_schema,
            )
            for md, _ in records:
                pattern = re.escape(name) + r"[^0-9a-f\n]{0,80}?([0-9a-f]{64})"
                for match in re.finditer(pattern, md.read_text()):
                    if match[1] not in versions:
                        found.append(f"{md.name}: unreachable {name} pin {match[1]}")
        except (OSError, ValueError, subprocess.CalledProcessError) as error:
            found.append(f"{name}: {error}")
    return found


def disposition_findings(records):
    """A verdict retaining a possible defect needs an explicit later
    disposition.
    """
    ids = {row["id"] for _, data in records for row in data["findings"]}
    found = []
    for md, data in records:
        for candidate in data.get("refutedCandidates", []):
            kept = any(v.get("adjustedSeverity") not in (None, "info")
                       for v in candidate.get("verdicts", []))
            if not kept:
                continue
            disposition = candidate.get("laterDisposition", {})
            routed = disposition.get("id") in ids
            explained = (disposition.get("status") == "informational"
                         and bool(disposition.get("reason")))
            if not (routed or explained):
                found.append(f"{md.name}: undisposed candidate {candidate['title']}")
    return found


def amendment_findings(records):
    """
    Latest document amendments and retained output bind actual present
    bytes.
    """
    found = []
    for md, data in records:
        amendments = data.get("documentationAmendments", [])
        if amendments:
            binding = amendments[-1]["reportDocument"]
            if binding["document"] != str(md.resolve().relative_to(ROOT)):
                found.append(f"{md.name}: current document path differs from its amendment")
            if binding["sha256"] != sha256(md.read_bytes()):
                found.append(f"{md.name}: current document SHA-256 differs from its amendment")
            bindings = [*amendments[-1].get("documentBindings", []),
                        *data.get("harnessDocumentationAmendments", [])]
            for document in bindings:
                path = ROOT / document["document"]
                if document["sha256"] != sha256(path.read_bytes()):
                    found.append(f"{md.name}: amended document SHA-256 differs: {path.name}")
        for output in data.get("remediationUpdate", {}).get("retainedOutput", []):
            path = ROOT / output["log"]
            # Raw output is local-only; absence in a public clone is not
            # corruption.
            if path.exists() and sha256(path.read_bytes()) != output["logSha256"]:
                found.append(f"{md.name}: retained output SHA-256 differs: {output['log']}")
    return found


def harness_syntax_findings(sources):
    """Parse retained Python harnesses without executing their audit
    work or rewriting historical reports.
    """
    found = []
    for name, source in sources.items():
        try:
            ast.parse(source, filename=name)
        except SyntaxError as error:
            found.append(f"{name}:{error.lineno}: invalid Python: {error.msg}")
    return found


def owns_open_until_commit_policy(text):
    """Read a report's own policy, excluding quoted finding evidence."""
    kept = []
    finding_depth = None
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced or line.lstrip().startswith(("|", ">")):
            continue
        heading = re.match(r"^(#+)\s+(.*)", line)
        if heading:
            depth = len(heading[1])
            if finding_depth is not None and depth <= finding_depth:
                finding_depth = None
            if re.search(r"\bAUD-\d+-(?:SEC|FUN|API|BLD|DOC|UI|ARC)\d+\b", heading[2]):
                finding_depth = depth
        if finding_depth is None:
            kept.append(line)
    prose = " ".join(" ".join(kept).split())
    return bool(re.search(r"stays? open (here )?until a commit records", prose))


def pair_findings(args, baseline, records):
    """Keep frozen pair checks with a context-aware policy check."""
    marker = ": the Markdown says each row stays open until a commit records it;"
    found = [line for line in baseline["check_pairs"](args) if marker not in line]
    for md, data in records:
        if not owns_open_until_commit_policy(md.read_text(encoding="utf-8")):
            continue
        for row in data.get("remediation", []):
            if (row["id"].startswith(data["auditId"] + "-") and
                    row.get("status") in ("fixed", "verified") and not row.get("fixCommit")):
                found.append(
                    f"{md.name}{marker} JSON remediation {row['id']} "
                    f"is {row.get('status')!r} with no fix commit"
                )
    return found


def self_test():
    """Wrong edits, missing links in a chain and unrouted verdicts must
    fail.
    """
    old, middle, current = b"old", b"middle", b"current"
    edges = [{"currentSha256": sha256(b), "auditedSha256": sha256(a),
              "reverseEdit": {"current": b.decode(), "audited": a.decode()}}
             for a, b in [(old, middle), (middle, current)]]
    def refuse_history(_):
        raise ValueError("unexpected historical lookup")
    if sha256(old) not in recover_versions(current, edges, refuse_history):
        raise RuntimeError("self-test: the complete chain must recover its oldest pin")
    for changed in [edges[:1], [{**edges[1], "auditedSha256": "0" * 64}]]:
        try:
            recover_versions(current, changed, refuse_history)
        except ValueError:
            pass
        else:
            raise RuntimeError("self-test: an incomplete or incorrect chain was accepted")
    if sha256(old) in recover_versions(current, edges[1:], refuse_history):
        raise RuntimeError("self-test: an unlisted oldest pin must remain unreachable")
    candidate = {"title": "test", "verdicts": [{"adjustedSeverity": "low"}]}
    records = [(Path("test.md"), {"findings": [{"id": "test"}], "refutedCandidates": [candidate]})]
    if not disposition_findings(records):
        raise RuntimeError("self-test: an unrouted low verdict was accepted")
    candidate["laterDisposition"] = {"id": "test", "status": "open"}
    if disposition_findings(records):
        raise RuntimeError("self-test: a routed verdict was refused")
    policy = "Each row stays open here until a commit records it."
    if not owns_open_until_commit_policy(policy):
        raise RuntimeError("self-test: an actual open-until-commit policy was missed")
    for quoted in [
        "| Evidence | " + policy + " |",
        "> " + policy,
        "```text\n" + policy + "\n```",
        "### AUD-024-DOC006 — historical contradiction\n\n" + policy,
    ]:
        if owns_open_until_commit_policy(quoted):
            raise RuntimeError("self-test: quoted evidence became the report's own policy")
    if not owns_open_until_commit_policy(
            "### AUD-024-DOC006\nOld finding.\n## Remediation\n" + policy):
        raise RuntimeError("self-test: a later remediation policy was missed")
    broken = "lines += local-only: `procedure.md` were applied.\"\n"
    if harness_syntax_findings({"assemble.py": broken}) != [
            "assemble.py:1: invalid Python: unterminated string literal (detected at line 1)"]:
        raise RuntimeError("self-test: the malformed procedure-reference edit was accepted")
    if harness_syntax_findings({"assemble.py": 'lines += ["local-only: `procedure.md`"]\n'}):
        raise RuntimeError("self-test: a valid local-only reference was refused")
    print("Audit-record controls passed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--schema", action="store_true")
    group.add_argument("--metadata-only", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    baseline = runpy.run_path(BASELINE)
    # The retained check resolves paths relative to the repository root.
    os.chdir(ROOT)
    raw_git = baseline["git"]
    def live_git(*commands):
        result = raw_git(*commands)
        if commands == ("ls-files",):
            names = result.stdout.splitlines()
            names += raw_git("ls-files", "--others", "--exclude-standard").stdout.splitlines()
            live = sorted(name for name in set(names) if (ROOT / name).is_file())
            result.stdout = "\n".join(live)
        return result
    baseline["check_links"].__globals__["git"] = live_git
    records = list(baseline["records"]())
    selected = ["pairs", "dates", "links"]
    if not args.metadata_only:
        selected.append("fixed_in")
    if args.schema:
        args.schema = str(WORKSPACE / PROCEDURES["audit-report.schema.json"])
        selected.append("schema")
    found = pair_findings(args, baseline, records)
    found += [item for name in selected if name != "pairs"
              for item in baseline[f"check_{name}"](args)]
    if not args.metadata_only:
        found += procedure_findings(records)
    found += disposition_findings(records)
    found += amendment_findings(records)
    harnesses = {
        name: (ROOT / name).read_text(encoding="utf-8")
        for name in live_git("ls-files").stdout.splitlines()
        if re.match(r"docs/audits/AUD-\d+-harnesses/.*\.py$", name)
    }
    found += harness_syntax_findings(harnesses)
    for item in found:
        print(item)
    if found:
        raise SystemExit(1)
    scope = "metadata" if args.metadata_only else "metadata and procedure pins"
    print(f"All {len(records)} audit-record pairs, links, dispositions and {scope} agree.")
    print(f"All {len(harnesses)} retained Python harnesses parse without executing audit work.")


if __name__ == "__main__":
    main()
