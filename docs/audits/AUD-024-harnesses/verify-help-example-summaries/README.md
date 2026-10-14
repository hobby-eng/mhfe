# Command summaries typed again (AUD-024)

Harness of audit AUD-024, written against commit b6fca69 of mhfe.

It checks that each command summary constant of the command-line tool (`pub const *SUMMARY: &str`
in `src/bin/mhfe/`) has one source: no other non-test line of `src/bin/mhfe/` types the same text
as a string literal. A file's lines from its first `#[cfg(test)]` on are not read, since a test may
type the value it expects (rule CORE-10; the recommended fix of AUD-023-ARC006 named the examples of
`mhfe --help`).

Inputs: the Rust sources under `src/bin/mhfe/`. No build, no network, no secrets.

Command, from the repository root:

    python3 docs/audits/AUD-024-harnesses/verify-help-example-summaries/summary_literals.py

Expected output at b6fca69 (exit code 1):

    src/bin/mhfe/main.rs:170 types SUMMARY of src/bin/mhfe/rekey.rs:110 again: 'Change the password or settings of a container'
    src/bin/mhfe/main.rs:172 types SUMMARY of src/bin/mhfe/wallets.rs:34 again: 'Open hidden wallets with other passwords'
    src/bin/mhfe/main.rs:175 types REPAIR_SUMMARY of src/bin/mhfe/container_repair.rs:128 again: 'Repair a container phrase with its repair words'
    11 summary constants, 3 literal copies

After a fix it prints `11 summary constants, 0 literal copies` and exits with 0.
