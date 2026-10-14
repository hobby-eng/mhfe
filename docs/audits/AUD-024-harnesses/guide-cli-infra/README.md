# guide-cli-infra harnesses (AUD-024)

Audit AUD-024, role guide-cli-infra, at commit b6fca69238344dd2525b06270ee6ff3b055e68c1 (branch
aud023-remediation). They check coding-guide conformance (code-core, code-rust) and the
architecture of the command-line tool's infrastructure in `src/bin/mhfe`. Every probe uses public
data only: the published zero-12 vector container and letters typed at a prompt. Each one stops
the tool before a secret could be accepted, so no Argon2 round runs at suite cost. Only the checks
at start run, with their reduced-cost public vectors.

Input: `MHFE`, a release binary built from the commit (`cargo build --locked --release`, the
baseline's `target/release/mhfe`). Linux x86-64, Python 3, `git`, and `cargo` for the mutation
harness. Run every command from the repository root.

## Harnesses that fail on a defect

Each of these prints `DEFECT REPRODUCED` and exits 1 while its defect is present. Once the defect
is fixed it prints `DEFECT NOT REPRODUCED` and exits 0.

| Script | What it checks | Command | Expected at b6fca69 |
| --- | --- | --- | --- |
| `cli_infra_probes.py` | P1: `yes \| mhfe repair` and `yes \| mhfe repair-words --count 4` without `--stdin` ask again without end. P2: the own-settings questions of `mhfe encrypt` ask a valid PIM again after a refused memory level, and ask the level before refusing PIM 5000. P3: an 8,192-byte answer is taken at a hidden prompt but refused with `--stdin` ("longer than 8191 bytes"), and 8,193 bytes at the prompt give "longer than 8192 bytes". | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/cli_infra_probes.py target/release/mhfe` | P1 still running after 3 s with about 350,000 lines; P2a and P2b DEFECT; P3 DEFECT; exit 1 |
| `stdout_guard_mutation.py` | Exports the commit into SCRATCH and adds a `println!` after the first `#[cfg(test)]` of style.rs, self_test.rs, choice.rs and startup.rs. `every_result_is_written_through_one_function` must then fail. A control mutant in menu.rs must fail too. | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/stdout_guard_mutation.py SCRATCH TARGET` (TARGET is the cargo target folder, `../tmp/aud024/target` in this audit) | the test passes with the four writes, and the control fails; exit 1 |
| `password_prompt_probe.py` | The container password prompt of `mhfe decrypt` explains the secret at TERM=xterm-256color but not at TERM=dumb. | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/password_prompt_probe.py target/release/mhfe` | the explanation is shown at TERM=xterm-256color and missing at TERM=dumb; exit 1 |
| `explanation_width_probe.py` | Types the public phrase "abandon ... about" into `mhfe encrypt` and presses `?` at the container-length question. It measures the lines written by `style::gives` and `style::costs`, which do not wrap (CORE-36, at most 78 columns). | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/explanation_width_probe.py target/release/mhfe` | widest line 79 columns; exit 1 |
| `isolation_report_probe.py` | Under a seccomp filter that makes `landlock_create_ruleset` return ENOSYS, as on a kernel without Landlock, the write ruleset is refused. `mhfe self-test` still reports "Isolation enforced", and the `encrypt` summary leaves "file writes" out without a warning. | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/isolation_report_probe.py target/release/mhfe` | "enforced"; "isolated network, no new sockets (kernel-enforced)"; no warnings; exit 1 |
| `static_evidence.sh` | Prints, from the commit itself (`git show`), the source lines that the static findings cite: S1 unwrapped style helpers (a 79-column `gives` line), S2 the "G10" plan cited but held nowhere, S3 duplicate output helpers, S4 values typed again, S5 the two answer-line limits, S6 the progress bar's own stages. S7 prints the settings question's loop for reading. | `bash docs/audits/AUD-024-harnesses/guide-cli-infra/static_evidence.sh` | `6 of 6 cited defects present`; exit 1 |

## Probes that record facts

These are not pass-or-fail checks of a defect.

| Script | What it records | Command |
| --- | --- | --- |
| `module_graph.py` | The dependencies between the tool's modules, from `crate::` references outside the tests, and their cycles. | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/module_graph.py src/bin/mhfe` |
| `stdout_scan_reach.py` | The production lines that the stdout guard test never reads: 1,389 at b6fca69. | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/stdout_scan_reach.py src/bin/mhfe` |
| `fn_lengths.py` | Functions longer than N lines outside the test modules (CORE-15). | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/fn_lengths.py 100 <files>` |

The following checks pass at b6fca69. Each exits 0, or prints its expected result, when the
earlier finding stays fixed:

| Script | AUD-023 finding | Command | Expected at b6fca69 |
| --- | --- | --- | --- |
| `colour_probe.py` | CORE-38 | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/colour_probe.py target/release/mhfe` | no colour codes at TERM=dumb, NO_COLOR=1 and CLICOLOR=0; colour with CLICOLOR_FORCE=1 |
| `typed_ahead_probe.py` | AUD-023-UI003 | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/typed_ahead_probe.py target/release/mhfe` | still waiting after the typed-ahead Enter; exit 0 |
| `dumb_typing_probe.py` | AUD-023-UI004 | `python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/dumb_typing_probe.py target/release/mhfe` | no control sequence after the prompt; exit 0 |

## Logs

The logs are in `docs/audits/AUD-024-evidence/guide-cli-infra/`. Each one was written by
`docs/audits/AUD-024-harnesses/run-logged.sh`, with a `.command.json` beside it:

| Log | Contents |
| --- | --- |
| g01, g02 | The first manual mutation run and its control. |
| g03 | `cargo clippy --bin mhfe -- -W unreachable_pub`: 422 unreachable `pub` items in the binary. |
| g04 | `cli_infra_probes.py` |
| g05 | `stdout_guard_mutation.py` |
| g06 | `static_evidence.sh` |
| g07 | `module_graph.py` |
| g08 | `stdout_scan_reach.py` |
| g09 | `fn_lengths.py` |
| g10 to g12 | The rechecks of earlier findings. |
| g13 | The output of `mhfe serve` and its refusal of a malformed checksum file. |
| g14 | The advice without a terminal. |
| g15 | The startup time. |
| g16 | `password_prompt_probe.py` |
| g17 | `isolation_report_probe.py` |
| g18 | `explanation_width_probe.py` |
