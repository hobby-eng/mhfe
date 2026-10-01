# AUD-005: decisions taken during the unattended run

The audit and its remediation ran unattended on 2026-10-01. Wherever more than one option was
reasonable, this file says what was chosen and why. The report is
[audit-05-2026-10-01.md](audit-05-2026-10-01.md). Nothing was pushed or tagged.

## Choices made

1. **Seven findings, all low.** None reaches medium: no suite 3 mismatch, no wrong phrase, no leak
   to another party. The phrase copies in freed memory (SEC001) are filed as security because they
   break a guarantee that SECURITY.md and API.md state, but as low because the process is
   short-lived, offline and its memory is discarded at exit.
2. **Weak passwords (FUN001): count different words.** A password made only of EFF words now needs
   four _different_ ones to avoid the warning. The alternative, warning about every repeat, would
   also warn about a short password with one accidental repeat among five words, which is still
   strong. A genuinely random four-word password repeats a word in about 0.08% of cases; it then
   gets the warning, whose text already says "unless it was chosen at random". Words are now
   compared with ASCII case folding instead of Unicode lowercasing, so no lowercased copy of the
   password is made; a word with a non-ASCII letter no longer counts as an EFF word, which can only
   add a warning.
3. **Warning wording.** The new text keeps the old phrase and adds "all different", so the AUD-005
   probe, committed before the fix, checks the same text before and after.
4. **Memory advice (UI001): keep the advice only for a free-memory refusal.** After a failed
   reservation the reported free memory has just proved too high, so no level is suggested at all
   rather than a guessed lower one.
5. **The AUD-004 record (DOC001).** AUD-004's statuses were updated in place with a dated,
   attributed follow-up rather than only in AUD-005, so that a reader of AUD-004 sees the current
   state. Its original findings and evidence are unchanged, and its Markdown was edited in place,
   not reformatted with Prettier, to keep the historical text intact. FUN001 and BLD001 of AUD-004
   were moved to verified on the strength of exact-commit CI runs (macOS tests, canonical and macOS
   packaging); these are external evidence, which the record says.
6. **Commits.** One commit for the baseline report and harnesses, one per code finding, one for the
   three documentation findings together, one for the AUD-004 record, and a last one that records
   the remediation in the AUD-005 report and adds this file. The report names each fix commit; a
   commit cannot name its own hash, which is why the record update comes last.
7. **Formatting.** As instructed, Markdown that was touched (README.md, API.md, the AUD-005 report,
   the audit index, the harness README) was formatted with Prettier and the mhfe_spec configuration.
   README.md and API.md therefore changed more lines than their fixes need; the rendered text is the
   same apart from the fixes. `web/client.d.ts` keeps its own style (single quotes, 120 columns),
   under which Prettier reports no change: the mhfe_spec configuration would have rewritten every
   quote in the file.
8. **Harnesses.** The allocator probe is a small Cargo package in
   `docs/audits/AUD-005-harnesses/phrase-copies/` with its own `Cargo.lock` and `[workspace]`, so it
   never joins the MHFE build and runs offline. The CLI probes stop `mhfe encrypt` with a 1 GiB
   address-space limit at the 2 GiB reservation, after the password has been judged and before any
   Argon2 work, which kept the "no full-size runs" rule.
9. **Report validator.** The AUD-005 validator checks the snapshot against the git objects of the
   reviewed commit rather than the working tree, so it keeps passing after the remediation commits
   (the AUD-004 validator fails by design once the source changes).
10. **Reasoning effort.** Recorded as unknown (`null`): the session does not expose the setting, and
    the agent file's header value was not used as evidence.

## Left for you

1. **Release.** The fixes are on `main` after `v0.4.0`, unpushed. They change the CLI and the
   WebAssembly core (not any suite 3 output), so they need CI, the full vector replay and a
   canonical build before a release. Push when you have looked at them.
2. **Promise-returning client methods that throw — resolved (owner's decision, 2026-10-01).** Every
   `MhfeClient` operation is now `async`: every error rejects its promise, argument checks included,
   and nothing is thrown at the call. The wallet tools' Deriver clears its password fields at the
   first progress report instead of right after the call, so a refused argument leaves the password
   in place. The version stays 0.4.0: its release is to be rebuilt with this change.
3. **Page callbacks that throw — resolved (owner's decision).** A throwing `onProgress` or
   `onUnverified` stops the operation, ends its worker and rejects with `CALLBACK_FAILED`, the
   page's error as the `cause`; later messages of that worker are ignored, and a late event of a
   stopped worker can no longer end a later operation.
4. **Prettier in this repository.** There is no Prettier configuration in mhfe, and 12 Markdown and
   JavaScript files differ from what the mhfe_spec configuration produces. Decide whether to add a
   configuration (and which style for the JavaScript) and reformat once.
5. **Independent verifier and Unicode 17 — resolved (owner's decision).** The verifier takes the
   Unicode 17.0.0 database from `unicodedata2` (hash-pinned in
   `scripts/independent-suite3-requirements.txt`), refuses to run on any other version, applies the
   whole password rule of the specification itself (UTF-8, controls, unassigned code points with
   the noncharacters, NFKD, length), and its new `passwords` command reproduces all 33 password
   cases of `validation-cases.json`; `vectors.yml` runs it.
6. **Workflow hardening — resolved (owner's decision).** Python packages install only with
   `--require-hashes`; every checkout sets `persist-credentials: false`; each release job hands
   its own checksums to `publish`, which checks every archive against them and that none is
   missing or extra before writing `SHA256SUMS`.
7. **Local canonical builds** send untracked and ignored files to Docker (they do not reach the
   archives); consider extending `.dockerignore` (for example `docs/audits/*-evidence`,
   `__pycache__`) and recording the source commit and a dirty flag in `BUILD-INFO.txt`.
8. **Still not run:** Docker and the reproducible build, full-size Argon2 and the full vector
   replay, and anything on Windows, macOS or ARM64 apart from the CI results quoted in the report.
   Release run 36823878528 of `v0.4.0` was still replaying the vectors when it was read.
