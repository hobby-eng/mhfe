#!/usr/bin/env python3
"""Audit AUD-024, role regression-aud023: does the AUD-023 remediation register name the files
that hold each fix?

For a set of AUD-023 findings, the fix site was found by reading the fix commit 253ca3c: a file and
a line that the commit added. The harness checks, at the reviewed commit (b6fca69 by default):

1. the fix line is in that file at the reviewed commit and was added by the fix commit;
2. the register's "Fixed in ..." list for the finding (JSON `remediation[].evidence`, the same text
   as the Markdown table) names that file.

It also reports, for every register entry with a "Fixed in" list, whether that list is exactly the
set of files outside docs/audits/ that mention the finding's ID, which is how the lists read.

Exit 0 when every fix site is named, 1 when one is not, 2 on a usage or repository error.

    python3 docs/audits/AUD-024-harnesses/regression-aud023/remediation_fix_sites.py [commit]
"""

import json
import re
import subprocess
import sys

FIX_COMMIT = "253ca3c38aef04f0f68c1cdb1130c14bfd2e7789"
RECORD = "docs/audits/AUD-023-2026-10-13.json"

# (finding, file at the reviewed commit, a line the fix commit added), each read in the fix
# commit's diff. A file that a later commit split (df07f21) names its path in the fix commit in
# MOVED_SINCE_FIX.
MOVED_SINCE_FIX = {"src/wasm_api/core/search.rs": "src/wasm_api/core.rs"}
FIX_SITES = [
    ("AUD-023-API001", "web/client.js", "passphrase is given beside the ${name}, not inside it."),
    ("AUD-023-API001", "src/wasm_api/core/search.rs",
     "refuse_unused_passphrase(passphrase, PassphraseReferences::Check).map_err(js_error)?;"),
    ("AUD-023-API002", "web/worker-runtime.js", "async function withSession(session, use) {"),
    ("AUD-023-API002", "web/core-worker.js", "return withSession(session, async () => {"),
    ("AUD-023-UI001", "web/client.js", 'requireSetting(pim, MAX_PIM, "INVALID_PIM", `${side}PIM`);'),
    ("AUD-023-UI005", "src/bin/mhfe/new_wallet.rs", 'long = "wallet-check",'),
    ("AUD-023-BLD010", "src/self_check/sets.rs", ".merge(master_key())"),
    ("AUD-023-ARC005", "src/self_check/sets.rs", "pub fn browser_process<'a>() -> SelfCheck<'a> {"),
    ("AUD-023-ARC005", "web/client.js", 'operation: "selfCheckProcess", tier: "full", skip'),
    ("AUD-023-ARC006", "src/self_check.rs",
     'pub(crate) const DAMAGED: &str = "the built-in cases are damaged";'),
    ("AUD-023-ARC016", "src/wasm_api/core.rs",
     "pub fn keep_old_container(pim: f64, memory_level: f64) -> Result<String, JsError> {"),
    ("AUD-023-ARC016", "web/client.js", "async keepOldContainer({ pim = 0, memoryLevel = 0 } = {}) {"),
    ("AUD-023-DOC001", "src/bin/mhfe/encrypt.rs", "--repair-words N the repair words on a second line"),
    ("AUD-023-DOC001", "src/bin/mhfe/diceware.rs",
     "private screen, which is cleared afterwards, or hidden where there is none"),
]


def git(*arguments):
    return subprocess.run(["git", *arguments], capture_output=True, text=True, check=True).stdout


def fixed_in(evidence):
    match = re.search(r"Fixed in (.*?)\. ", evidence)
    return [] if match is None else [name.strip() for name in match.group(1).split(",")]


def main(arguments):
    if len(arguments) > 1:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    commit = arguments[0] if arguments else "b6fca69"
    try:
        record = json.loads(git("show", f"{commit}:{RECORD}"))
    except subprocess.CalledProcessError as error:
        print(f"cannot read {RECORD} at {commit}: {error.stderr.strip()}", file=sys.stderr)
        return 2
    lists = {entry["id"]: fixed_in(entry["evidence"]) for entry in record["remediation"]}

    print(f"Register entries whose 'Fixed in' list equals the files that mention the ID ({commit}):")
    equal = 0
    with_list = 0
    for finding, names in lists.items():
        if not names:
            continue
        with_list += 1
        mentioned = git("grep", "-l", "-F", finding, commit, "--", ".", ":!docs/audits")
        files = sorted(line.split(":", 1)[1] for line in mentioned.split())
        if sorted(names) == files:
            equal += 1
    print(f"  {equal} of {with_list}")

    missing = 0
    fix_diff = {}
    for finding, path, line in FIX_SITES:
        path_at_fix = MOVED_SINCE_FIX.get(path, path)
        if path_at_fix not in fix_diff:
            fix_diff[path_at_fix] = git("show", FIX_COMMIT, "--", path_at_fix)
        added = any(row.startswith("+") and line in row
                    for row in fix_diff[path_at_fix].splitlines())
        present = line in git("show", f"{commit}:{path}")
        named = path in lists.get(finding, [])
        state = "named" if named else "NOT NAMED"
        print(f"{finding}: {path}: fix line added by {FIX_COMMIT[:7]}: {added}; "
              f"present at {commit}: {present}; register: {state} (lists {lists.get(finding)})")
        if not (added and present):
            print("  the fix site itself was not found; the harness needs updating", file=sys.stderr)
            return 2
        missing += not named
    if missing:
        print(f"FAIL: {missing} fix sites of {len(FIX_SITES)} are missing from the register's "
              "'Fixed in' lists")
        return 1
    print(f"OK: every one of {len(FIX_SITES)} fix sites is named by the register")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
