# AUD-017 R4: build, release, architecture, documentation and audit records

Audit-only probes of reviewer R4 of AUD-017, an ordinary compact-team audit of mhfe. The reviewed
source is the uncommitted 0.5.1 working tree on commit `3c60594` (source fingerprint
`b2addb36…cbc7`). The probes only read the repository (and, for the commit and procedure checks, the
sibling `mhfe_spec` and `multi-chain-wallet-tools` checkouts); none builds, runs Argon2 or uses the
network. Each exits 1 when it reproduces a defect. Run them from the repository root through the
audit's runner, which keeps the output in the ignored `docs/audits/AUD-017-evidence/r4-<label>.log`:

```sh
python3 docs/audits/AUD-017-harnesses/run.py r4-<label> <command ...>
```

| Probe                       | What it checks                                                                                              | Expected on the reviewed tree |
| --------------------------- | ----------------------------------------------------------------------------------------------------------- | ----------------------------- |
| `no_copies_gate.sh`         | The copy gate of `scripts/check.sh` (`scripts/verify-no-copies.mjs`) passes                                  | exit 1: three copies          |
| `docker_vs_check.py`        | The canonical container runs every `check.sh` step its comment says it runs                                  | exit 1: eight steps missing   |
| `typed_defaults.py`         | The `--scan-gap` default is derived from `search::DECOY_SCAN_GAP` and the option is declared once            | exit 1                        |
| `api_md_decrypt.py`         | `docs/API.md` names every option of `MhfeClient.decrypt()` in `web/client.d.ts`                              | exit 1: `passphrase`          |
| `records_md_json.py`        | AUD-009..AUD-015 Markdown registers agree with their JSON; index rows and links; harness READMEs             | exit 0                        |
| `record_commit_prose.py`    | Every 40-hex commit name in the audit records and release notes resolves in mhfe, mhfe_spec or multi-chain   | exit 1: see the log           |
| `procedure_reverse_edit.py` | `docs/audits/procedure-changes.json` reverse edits give the audited procedure bytes                          | exit 0                        |

`record_commit_prose.py` also reports 40-hex values that are not commits of these repositories
(RustSec database commits, upstream Argon2 and XNU revisions, a rustc commit, and the commit the
AUD-015 review started at before a rewrite); read its log for the context of each. The AUD-015
probes of `AUD-015-harnesses/r5-build-docs/` were rerun through the same runner under
`r4-aud015-<name>` labels. Public test data only.
