# AUD-010 probes: secrets and security

Probes of the secrets-security reviewer of AUD-010 (CHECK-SEC-001, -003, -004, -005 and -007), for
the MHFE working tree on HEAD `d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0` with source fingerprint
`372da577dd586932d6b3fa47711d97bc25b8fa908a980cd2373b704724ec796b` (227 paths,
`../fingerprint.mjs`). They read the working tree and the local build that `scripts/check.sh` made
(`dist/`, `target/wasm-bindgen/`, `target/release/mhfe`), build nothing, run no Docker and no
Argon2 above its 256 MiB known answer, use public synthetic secrets only, write nothing outside a
temporary folder, and exit non-zero when a check fails. Run them from the repository root through
`../run-logged.sh`, which keeps the log in the ignored `docs/audits/AUD-010-evidence/`:

```sh
docs/audits/AUD-010-harnesses/run-logged.sh secrets-security-<name> <command>
```

| Script                      | Needs                                                                    | Checks                                                                                                                                                                                                  | Result at the reviewed state                                                  |
| --------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `network-scan.mjs`          | `dist/`, `web/`, `src/`                                                  | No network or remote-loading API in any package script outside reviewed local-only uses; no socket code in Rust outside `src/bin/mhfe/serve.rs` and unit tests                                          | Passes                                                                        |
| `wasm-residue.mjs`          | `target/wasm-bindgen/mhfe.js`, `dist/runtime/mhfe.wasm`, `dist/core/argon2-st.js` | Copies of passwords, passphrases, dice digits and phrases left in the WebAssembly's linear memory after each binding returns, sessions after `free()`; Argon2 rounds at 256 KiB, one pass             | Fails: a phrase passed as text leaves its copy (`describePhrase`, `walletFingerprint`, `encrypt`) |
| `client-lifecycle.mjs`      | `web/runtime.js`, `web/client.js`, `web/passwords.js`, `web/wallet.js`   | Every page copy of a secret is transferred or wiped on refused repetitions, failed worker starts, cancellation, late answers and hidden-wallet sessions; every secret field is in the transfer list | Passes                                                                        |
| `random-source.mjs`         | as `wasm-residue.mjs`                                                    | Sources that throw, fill nothing or repeat are refused; the full self-checks fail a stuck or narrow source; no request above 65,536 bytes; a failed generation leaves no part of the password        | Passes                                                                        |
| `cli-process-protection.py` | `target/release/mhfe`, Linux                                             | While `encrypt --stdin` and `decrypt --stdin` wait for their first answer: core file size 0, not dumpable, seccomp and no_new_privs on every thread, an empty network namespace                          | Passes                                                                        |
| `builder-paths.mjs`         | `dist/`                                                                  | No absolute path under a home directory in a file of the package                                                                                                                                        | Fails: 21 paths under the local `CARGO_HOME` in `runtime/mhfe.wasm`           |

`cli-process-protection.py` starts the tool with standard input on a pipe it never writes and stops
it with SIGKILL; set `TMPDIR` to choose where its temporary folder goes.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: f4f7b017d21cbda51283f9eaa973a0cc161b95d6 -> d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0.
