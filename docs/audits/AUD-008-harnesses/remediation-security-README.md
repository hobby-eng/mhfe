# AUD-008 focused security remediation verification

These new probes recheck SEC001–SEC004 after signed remediation commit
`082ac0b65cd92fda767c34d972058d22d2e49a0e` and namespace commit
`e854d6ed582321636d44b6423cf965df5b42e32d`. They preserve the original audit harnesses and
evidence. They use only the published `7f…7f` BIP39 vector and synthetic passwords, run no Argon2,
and make no blockchain or remote network requests.

Run from the authoritative MHFE checkout with the workspace Rust toolchain. First build the current
library through the normal targeted checks; the runner uses the most recent existing debug rlibs and
records their SHA-256 values rather than starting another Cargo build.

```sh
python3 -B docs/audits/AUD-008-harnesses/record-command.py --label remediation-security --timeout 90 -- python3 -B docs/audits/AUD-008-harnesses/remediation-security.py
```

Use another unused label for a replay. The runner emits source, library and harness hashes before
compilation. Generated probe source and executable stay in ignored local evidence.

- SEC001 includes the exact current production isolation module. It samples all five syscall errors
  before isolation, then requires `EACCES` for `socket`, `socketpair`, `io_uring_setup`,
  `io_uring_enter`, and `io_uring_register` after isolation and in four new concurrent worker threads.
  All four must inherit the main thread's network namespace, start, and join successfully. Invalid ring
  descriptors make the latter two probes bounded; the filter must reject them before ordinary
  descriptor validation. It exits 77 if the outer environment already returns `EACCES`, which would
  prevent attributing that result to MHFE. It does not establish general egress prevention for
  inherited descriptors or every asynchronous opcode.
- SEC002 forces a moving allocator and inspects released allocations while they remain valid. A
  historical `Mnemonic::to_string()` control must leave at least one unwiped public mnemonic prefix;
  the current public formatter must leave none and must reserve its final capacity. Source assertions
  bind the CLI to that formatter. Register, compiler and stack copies are outside this observation.
- SEC003 moves sixteen synthetic maximum-width `Password` values into the exact current retained
  vector type. Their underlying pointers must stay unchanged, and `/proc/self/smaps` must show all
  sixteen still locked. The runner exits 77 if the environment refuses the initial memory lock.
  Windows and browser builds do not supply this Unix memory-lock guarantee.
- SEC004 extracts the exact current Unix same-terminal predicate and checks two independently opened
  PTYs, a duplicated descriptor, `/dev/null`, and an invalid descriptor. Source assertions confirm
  both private-wallet commands call the guard. This probe alone is not a full CLI dispatch test;
  `scripts/verify-hidden-input.py` provides the independent split-terminal dispatch gate.

Exit 0 means these scoped assertions passed. A nonzero assertion or compilation error is a failed
check; exit 77 means a blocked environmental prerequisite. No Windows/macOS runtime, full-size
Argon2, release archive or reproducible build was performed by these probes.
