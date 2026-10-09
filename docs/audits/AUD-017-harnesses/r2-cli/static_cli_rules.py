#!/usr/bin/env python3
"""AUD-017 R2: static checks of the native command line (no build, no Argon2).

Run from the mhfe repository root:

    python3 docs/audits/AUD-017-harnesses/r2-cli/static_cli_rules.py

Checks (each prints PASS or DEFECT):
  S1  the "built-in check finds N words, not the M you gave" message is built in one place
      (workspace rule 6, DRY); a defect lists every copy in src/bin/mhfe.
  S2  the rekey front end does not decide itself which confirmations the library accepts after
      LENGTH_DIFFERS (rule 10, delegation): no built_in_check_lengths() test in rekey.rs.
  S3  the BIP39-passphrase question that decrypt asks for the 16-bit source check has a
      command-line option for its non-secret answer (owner rule: every menu answer is also an
      option); a defect when decrypt.rs asks it and its Options carry no passphrase flag.
  S4  the repair-word count asked when a container is made (encrypt, new, rekey) has an option.
Exits 1 when any check reproduces a defect, 0 otherwise.
"""
import re
import sys
from pathlib import Path

CLI = Path("src/bin/mhfe")
defects = 0


def report(name, ok, detail):
    global defects
    print(f"{name}: {'PASS' if ok else 'DEFECT'} - {detail}")
    if not ok:
        defects += 1


def lines_matching(pattern):
    found = []
    for path in sorted(CLI.glob("*.rs")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(pattern, line):
                found.append(f"{path}:{number}")
    return found


copies = lines_matching(r"built-in check finds \{")
report("S1", len(copies) <= 1, f"{len(copies)} copies: {', '.join(copies)}")

rekey = (CLI / "rekey.rs").read_text()
owner_rule = [m.start() for m in re.finditer(r"built_in_check_lengths\(\)\.contains", rekey)]
report("S2", not owner_rule, f"{len(owner_rule)} front-end test(s) of the owner's eligibility in rekey.rs")


def options_block(text):
    match = re.search(r"pub struct Options \{(.*?)\n\}", text, re.S)
    return match.group(1) if match else ""


decrypt = (CLI / "decrypt.rs").read_text()
asks = "ask_passphrase_explained" in decrypt
has_option = re.search(r"passphrase", options_block(decrypt), re.I) is not None
report("S3", not asks or has_option,
       f"decrypt asks the passphrase question: {asks}; an option answers it: {has_option}")

creating = {name: (CLI / f"{name}.rs").read_text() for name in ("encrypt", "new_wallet", "rekey")}
missing = [name for name, text in creating.items()
           if "ask_when_creating" in text and not re.search(r"repair[_-]?(words|count)",
                                                            options_block(text))]
report("S4", not missing, f"commands asking the repair-word count without an option: {missing}")

sys.exit(1 if defects else 0)
