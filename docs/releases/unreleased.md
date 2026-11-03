# Next release notes — draft

Record user-visible changes here as they are made. Before tagging, move them into
`docs/releases/v<version>.md`: the release workflow attaches that file as the text of the draft
release. Without it the canonical job fails before its build and no draft is made, while the macOS
builds and the CI checks of the same run go on until they end or are cancelled.

## Changed

- **mhfe-core.** The cipher, the password rules, native Argon2 and the protection of secrets now come
  from the crate mhfe-core. Containers, phrases, repair words and check words stay the same.
- **Nothing secret reaches swap on Linux.** A command that reads secrets forbids itself swap before it
  starts. Where it cannot and swap is not encrypted, it asks whether to go on.
- **Isolation on every system.** Every command but `serve` closes itself off before it reads
  anything, and the summary says what holds. On Windows the network stays open, and the summary warns
  of it.
- **Secrets stay in locked memory:** the BIP32 keys, the word hints and more of what used to sit in
  ordinary memory. On Linux they lie in the kernel's secret memory where it is offered.
- **The menu runs each command as a process of its own.** A crash no longer takes the menu with it.
- **`mhfe check` can answer "not verified".** A 24-word phrase without an address or fingerprint gets
  this answer, not "does not match". The exit code stays 3.
- **`mhfe check` names every length that matches.**
- **`--stdin` at a terminal changes nothing,** so a typed secret stays hidden.
- **A refused command line no longer repeats what was typed.**
- **The menu offers passwords from real dice.**
- **A new phrase with the wallet check takes a minute or two more:** it is drawn on one thread, as the
  specification's proof requires.
- **Passwords follow Unicode 18.0.0,** as specification 0.7.0 does.
- **`mhfe test-vectors` is gone.** The test vectors live in the specification's repository.
- **A wrong answer is asked again.** At a terminal, a container that the command cannot use, a
  phrase too long for `--same-length`, and a line too long or not UTF-8 no longer end the command.
- **Every help ends with the safety line.**

## Removed

- `mhfe new` no longer asks for a chosen word, and `--never-use` is gone. Every word of a new phrase
  is random. The browser package keeps its chosen word.

## Fixed

- Ctrl+C while a typed line or a phrase was being drawn could leave its last part, such as the hint
  below a password, on the main screen.
- A key pressed early no longer clears a private screen.
- Ctrl+C, Ctrl+\ and Ctrl+Z end a command in its checks at start too.
- Ctrl+D at any empty prompt cancels, with exit code 130.
- A result that cannot be written ends with exit code 1, and no longer as a success or a crash.

## Browser package

- `check()` gives `outcome` beside `matches`.
- `drawPhrase()` uses one worker: its `workers` option is gone. It also refuses a repetition of a
  passphrase that was not typed.
- A self-check part that failed closes the class even if its worker then crashes.
- The Argon2 builds clear their stacks and run only in a worker.
- `cancel()` is no error any more: the operation resolves to `CANCELLED`, `{ cancelled: true }`.
  `MhfeCancelledError` and the code `CANCELLED` are gone.
- `drawPhrase()` gives up with `RANDOM_FAILED` after 64 times the draws it expects.
- The export `checkPassword` is gone; `encrypt` and `decrypt` check the password as before.
- `make()` with a `count` for "checkWord", and an owner's answer to `onConfirmAgain` with a length
  the owner cannot compare, are refused by the library with `INVALID_REQUEST`, no longer by a
  `TypeError` of the class.
- `MhfeRepair`'s check at start also covers the seed, BIP32 and the hashes of the fingerprint.

## Library

- `Mhfe`, `Password`, `Suite`, `WorkFactor`, `Phrase`, `Argon2Engine` and `NativeArgon2` are
  mhfe-core's. The operations are functions that take `Mhfe` first.
- `CheckOutcome` has a third value, `NotVerified`.
- An operation that a callback can stop returns `Outcome<T>`, `Continue` with its result or
  `Break`; `MhfeError::Cancelled` is gone. `repair`, `new_password` and `wallet` refuse with errors
  of their own, which turn into `MhfeError`.
- `check_container`, `recover_confirmed`, `SelfCheckReport::warnings` and `require_passed` are gone:
  use `ContainerFacts::read`, `rekey::Rekey` and `first_failure()`.
- Removed or replaced: see `docs/API.md`.

## Build, tests and release

- A clone needs `--recurse-submodules`: the vectors come from the specification.
- The tools are `cargo xtask`, dprint replaces Prettier, and Node.js is gone.
