# Documentation

Start with the [main README](../README.md) for installation, the menu and each task.

| Document                                                    | What to use it for                                                                      |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| [Command-line reference](CLI.md)                            | Terminal input, script answers, wallet references, exit codes and download verification |
| [How MHFE works](HOW-IT-WORKS.md)                           | Container formats, recovery checks, hidden wallets, decoys and repair-card limits       |
| [Security](../SECURITY.md)                                  | Reporting a vulnerability, secret memory, process isolation and browser limits          |
| [Rust and WebAssembly API](API.md)                          | Library operations, callbacks, data types, outcomes and error codes                     |
| [Browser package](BROWSER-PACKAGE.md)                       | Embedding the modules and presenting their results in a page                            |
| [Building and checking MHFE](DEVELOPMENT.md)                | Source builds, tests, generated tables and implementation choices                       |
| [Preparing a release](RELEASING.md)                         | Canonical builds, checksums, signatures and publication                                 |
| [Release notes](releases/)                                  | Changes and compatibility for each version                                              |
| [Measurements](measurements/README.md)                      | Dated timing records and their limits                                                   |
| [Audit reports](audits/README.md)                           | Findings, reviewed snapshots and retained verification evidence                         |
| [Third-party notices](../THIRD_PARTY_NOTICES.md)            | Licences of bundled code and data                                                       |
| [Argon2 provenance](../vendor/phc-winner-argon2.md)         | Pinned reference C source used in the browser build                                     |
| [EFF word-list provenance](../vendor/eff-large-wordlist.md) | Password word list, its origin and licence                                              |

The [protocol specification](https://github.com/hobby-eng/mhfe-spec) defines the container formats
and optional checks and repair formats, with published test vectors. The [mhfe-core
repository](https://github.com/hobby-eng/mhfe_core) contains the protocol crate and its security
notes.
