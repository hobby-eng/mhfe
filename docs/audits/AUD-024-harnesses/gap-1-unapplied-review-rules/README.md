# AUD-024 gap-1-unapplied-review-rules harness

Audit AUD-024, role gap-1-unapplied-review-rules, at commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`.

`verify_review_rules.py` checks review rules of the workspace coding guide that no gate enforces
(CORE-37, CORE-17, CORE-33, CORE-10/14/18) and two behaviours of `mhfe test-vectors`. No check runs
Argon2: help screens do no work, and both `test-vectors` cases end before their first vector.
Public test data only (the published fixture `tests/fixtures/suite3-vectors/zero-12.json`).

| Check | What passes |
| --- | --- |
| `every_help_screen_ends_with_the_yellow_safety_line` | `-h` and `--help` of the 13 commands and `packaging/mhfe-fast-mode.py --help` end with a bold yellow line (CORE-37) |
| `every_help_screen_has_grey_notes_at_its_end` | the last line before the safety line of each of those screens is grey (CORE-37) |
| `test_vectors_refuses_an_only_that_matches_no_vector` | `mhfe test-vectors --output <new folder> --only zero-13` exits non-zero |
| `test_vectors_reports_an_unreadable_vector_as_unreadable` | with a truncated `zero-12.json` in the folder, `--only negative-cases` does not say the vector is missing |
| `no_source_says_expected_value_for_a_known_answer` | no "expected value(s)" in `src/`, `web/`, `scripts/` (GLOSSARY.md, Known answer, _Avoid_) |
| `every_option_family_has_a_terminal_suite_case` | the terminal suite runs `--scan-gap`, `check --path`, `password --check-word`, `--repair` of decrypt, rekey and wallets, `--passphrase-used` of decrypt and rekey, `rekey --repair-words` and `test-vectors --only` (CORE-33) |
| `the_browser_suite_runs_a_search_wallet_that_finds_the_word` | `scripts/browser-check/` calls `searchWallet` other than as an expected refusal (CORE-33) |
| `test_tools_takes_its_engine_facts_and_names_from_their_sources` | `src/bin/mhfe/test_tools.rs` no longer types the engine's SSSE3 choice, "4 threads", the `SHA256SUMS` name or a time estimate |

Inputs: a built `mhfe` binary of the commit (a debug or release build); Python 3; git. The optional
second argument is the folder for the temporary `test-vectors` output folders (the system's
temporary folder when omitted); they are removed at the end.

Command, from the repository root:

```bash
python3 docs/audits/AUD-024-harnesses/gap-1-unapplied-review-rules/verify_review_rules.py <path to mhfe> [<scratch folder>]
```

Expected output at b6fca69: eight `FAIL` lines, then `0 of 8 checks pass`, exit code 1. Once the
findings of this role are fixed, eight `PASS` lines, `8 of 8 checks pass`, exit code 0. The audit's
run is `docs/audits/AUD-024-evidence/gap-1-unapplied-review-rules/verify-review-rules.log`.
