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

## Removed

- `mhfe new` no longer asks for a chosen word, and `--never-use` is gone. Every word of a new phrase
  is random. The browser package keeps its chosen word.

## Fixed

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

## Library

- `Mhfe`, `Password`, `Suite`, `WorkFactor`, `Phrase`, `Argon2Engine` and `NativeArgon2` are
  mhfe-core's. The operations are functions that take `Mhfe` first.
- `CheckOutcome` has a third value, `NotVerified`.
- Removed or replaced: see `docs/API.md`.

## Build, tests and release

- A clone needs `--recurse-submodules`: the vectors come from the specification.
- The tools are `cargo xtask`, dprint replaces Prettier, and Node.js is gone.
