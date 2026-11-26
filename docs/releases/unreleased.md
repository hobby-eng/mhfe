# Next release notes — draft

Record user-visible changes here as they are made. Before tagging, move them into
`docs/releases/v<version>.md`: the release workflow attaches that file as the text of the draft
release. Without it the canonical job fails before its build and no draft is made; the macOS job,
which needs the canonical one, does not run, while the CI checks of the same run go on until they
end or are cancelled.

MHFE 0.8.0 no longer makes seed phrases: it encrypts, recovers, checks, rekeys and repairs the
phrase you already have. Containers, passwords and the specification are unchanged, so every
container made with 0.4.0 to 0.7.0 opens as before.

## Removed

- **`mhfe new` and its menu entry.** Create the wallet with your hardware wallet or another wallet
  program, write the phrase down, then encrypt it with `mhfe encrypt`. The Deriver of the
  [multi-chain wallet tools](https://github.com/hobby-eng/multi-chain-wallet-tools) makes a phrase
  that passes the phrase + passphrase check; MHFE still evaluates that check when it recovers one.
  The menu entries now start with Encrypt.
- **Chosen words.** A word chosen for a new phrase, and a word it must not hold, went with it.
- **Browser package:** `MhfeWallet` loses `drawPhrase()`, `describeDraw()` and `cancel()`, their
  types, and the parameters `drawReportInterval`, `maxChosenWords`, `maxNeverUseWords` and
  `recommendedRandomBits`. `walletCheck()`, `fingerprint()`, `describeAddress()` and `wordHints()`
  stay. The wallet module draws nothing at random any more, so its self-check has neither the
  `word-wishes` nor the `random-source` part, and the raw `selfCheckWallet` takes no random source.
  The error codes `PASSPHRASES_DIFFER` and `INVALID_WORD_WISH` are gone, and `wallet/wallet.js` no
  longer re-exports `CANCELLED` and the type `MhfeCancelled`, which none of its methods returns;
  take them from `runtime/runtime.js` where a page needs them.
- **Rust library:** the module `word_wishes`; `PhraseDraw`, `NewPhrase`, `require_same_passphrase`,
  `NEW_ENTROPY_BYTES`, `DRAW_REPORT_INTERVAL` and `DRAW_LIMIT_FACTOR` of `wallet_check`; and the
  argument of `self_check::sets::wallet()`, which takes no random source now. `wallet_check::verify`,
  `phrase_passes` and `require_passphrase` stay.

## Security

- **A command stops before its first question when other programs could read its memory**: on
  Linux in a sandbox such as Flatpak, a container, a user namespace its user owns or under a
  debugger, and on macOS in a program without the hardened runtime. It used to warn and go on.
- **Commands refuse what they never need**: on Linux file locks, `sendmsg` and signals to any
  other process, on Windows new executable code and DLLs that Microsoft did not sign.
- **A command closes the files and connections it was started with** before it isolates itself,
  on Linux and macOS, as isolation would leave them usable. The warning at start names any that
  stayed open.
- **The isolation warning names more of what stays open:** file writes on macOS too, and
  protections that cover only some threads.
- **`mhfe serve` opens the browser by a fixed path** on macOS (`/usr/bin/open`) and Windows
  (`System32\cmd.exe`), so a `cmd.exe` placed next to `mhfe.exe` no longer runs. The browser gets
  no terminal, and Ctrl+C in the server no longer reaches it.
- **The menu starts its commands from the program file it runs** on Linux, not from its path
  again, and a stop it passes on can no longer reach another process that took an ended command's
  number.
- **The macOS programs run with the hardened runtime.** Their ad-hoc signature, still reproducible,
  now carries it, and the Intel program, which had no signature, gets the same one. macOS then
  gives their memory to no other process, not even to root or to a debugger on a Mac with the
  developer tools turned on, while System Integrity Protection is on.
- **Names in messages show invisible formatting characters escaped**, such as U+202E, which could
  show a file name reversed.

## Builds

- **mhfe-core moves to its next version**: it takes the protection of secrets and the isolation
  from secret-protection-core 0.2.0, and the repair words' code from reed-solomon-core 0.2.0. Cards
  and repairs are unchanged.
- **The macOS archives are reproducible too.** Zig links them in the same Docker build as the
  other four, without Apple's SDK, so all six archives can be rebuilt byte for byte and compared
  with the published ones. The release workflow then runs the self-test and the terminal suite of
  both macOS programs on a Mac.
- **Fuzz targets read what a person types**: addresses, derivation paths and fingerprints; phrases,
  containers and repair cards; passwords and dice rolls. The release runs each for 90 seconds, and
  the RustSec check reads their lockfile too.
- **CI runs the tests on ARM64 Linux and on Windows with the GNU toolchain**, those of the
  released programs, as well as with MSVC.
- **The release draft is made without the repository's code.** The canonical job hands the notes
  on as an artifact; the attestation job may sign but not write, and only the job that creates
  the draft with `gh` may write. Neither checks out the repository.
- **Ctrl+C, SIGTERM and a closed terminal** are handled by MHFE itself on Linux and macOS, as
  before; the `ctrlc` crate stays for Windows only, and with it six crates leave the Linux and
  macOS programs.

## Documents

- Every command in the README and in docs/CLI.md has examples, and the README describes an offline
  live system as the recommended way to work. The two container formats are called by what they are,
  24-word and same-length, beside their suite names.
