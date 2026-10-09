# AUD-015 R5: build, release, architecture, documentation and audit records

Audit-only probes of reviewer R5 of AUD-015, an ordinary audit of mhfe. The reviewed source is
the uncommitted working tree on commit `4c3a6909bced0f0907f61ae291b11bb6bb419689` (source
fingerprint `f79444dc…2a93`); during the review an owner-authorized privacy rewrite replaced
that commit by `ca0086acf545d07bfe008ae340554124a48442bf` without changing `src/`, `web/`,
`scripts/` or `tests/`, and a second one later that day by
`abb16671b641378c0fc3c4d855f8d126498e754b`, which changed one comment in `src/`. The probes read the repository and change nothing in it. Each exits
non-zero when it finds what it looks for. Run them from the repository root, each through the
audit's runner so that its output and record stay in the ignored `docs/audits/AUD-015-evidence/`:

```sh
python3 docs/audits/AUD-015-harnesses/run.py r5-<label> <command ...>
```

| Probe                             | What it checks                                                                                                                    | Inputs                                                    |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `markdown_links_lists.py`         | Relative links and anchors of the Markdown files resolve; no blank line inside a list (the workspace rule)                        | optional file list; default every non-audit `*.md`        |
| `capture_help.sh`                 | Prints `--help` and `-h` of every command without colour                                                                          | path of a built `mhfe`                                    |
| `documented_options.py`           | Every `mhfe <command> --option` in the documents is declared by that command                                                      | the log of `capture_help.sh`                              |
| `documented_symbols.py`           | Every Rust or browser name and error code in the documents is declared in `src/` or `web/`                                        | none                                                      |
| `typed_again_lists.py`            | Word-count lists spelled by hand in message strings instead of derived from their constants (AGENTS.md, rule 6)                   | none                                                      |
| `audit_redaction_diff.py`         | An audit record against an older version: what changed besides home paths, time zones, table padding and, optionally, commits     | `[--ignore-commits] [BASE [NEW_HEAD]]`                    |
| `redaction_vs_saved_originals.py` | The redacted audit files against their exact pre-redaction bytes, kept outside the repository by the redaction session            | two AUD-015 snapshot manifests and the folder of `.blob`s |
| `history_rewrite_map.py`          | Pairs the old and new history, lists tree changes outside `docs/audits/` and `docs/measurements/`, and records naming old commits | old and new head (the old objects must still exist)       |
| `record_commit_fields.py`         | Commit fields of the JSON records (`fixCommit`, `verificationCommit`, …) name commits of the current history                      | none                                                      |
| `harness_bindings.py`             | File SHA-256 values that the records bind still match the files, or a privacy binding explains the change                         | none                                                      |

Expected output on the reviewed tree: `markdown_links_lists.py`, `documented_options.py` and
`documented_symbols.py` report no problem (exit 0); `typed_again_lists.py` reports five message
strings (exit 1); `record_commit_fields.py` reports 48 fields naming replaced mhfe commits, unreachable before the
prune and missing after it, and four naming mhfe_spec commits that no longer exist (exit 1);
`harness_bindings.py` reports nine broken bindings (exit 1). `history_rewrite_map.py` ran while
the old commits still existed; the redaction session pruned them at about 23:54 UTC, after which
it cannot run again. Public test data only; no Argon2, network, build or Docker.
