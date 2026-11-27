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
  argument of `self_check::sets::wallet()`, which takes no random source now.
  `wallet_check::verify`, `phrase_passes` and `require_passphrase` stay.

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
  no terminal: on Linux and macOS it starts in a session of its own, which can neither read the
  server's terminal nor type into it, and Ctrl+C in the server no longer reaches it.
- **The menu starts its commands from the program file it runs** on Linux, not from its path
  again, and a stop it passes on can no longer reach another process that took an ended command's
  number.
- **The macOS programs run with the hardened runtime.** Their ad-hoc signature, still reproducible,
  now carries it, and the Intel program, which had no signature, gets the same one. macOS then
  gives their memory to no other process, not even to root or to a debugger on a Mac with the
  developer tools turned on, while System Integrity Protection is on.
- **Names in messages show invisible formatting characters escaped**, such as U+202E, which could
  show a file name reversed, and the soft hyphen and the tag characters, which show nothing.
- **The isolation warning names the extra refusals that did not take effect**, and the question
  about unencrypted swap comes only after the checks at start, which may stop the command anyway.
- **Ctrl+C during `mhfe decrypt` with several passwords** leaves the private screen only after a
  password or phrase being drawn there is whole, and nothing is drawn after it: before, a heading
  or a line drawn again could reach the main screen.
- **Browser package:** a password, passphrase, phrase or other secret of more than 8192 bytes, more
  than any answer the command-line tool reads, is refused with the new code `SECRET_TOO_LONG`
  before the worker gets it, also from a `Uint8Array` subclass that reports a smaller length.
- **Ctrl+C while a private screen closes** no longer ends the tool with the screen still showing
  what was typed: entering and leaving it and every cancel take turns.
- **Restoring the terminal no longer waits for its output** on Linux and macOS, so Ctrl+C ends the
  tool at once also while the terminal's output is held.
- **Ctrl+C after an unverified container was shown** always says that it is not verified: from
  its first word on, and after a failed check too.
- **The search for missing container words** wipes its copies of the container's word numbers.
- **Browser package:** a worker wipes the secrets it was given before it replies, as the page ends
  it on the reply; a container phrase or card of more than 8192 characters is refused before it
  reaches the worker.
- **The Windows launcher `mhfe-launch.bat`** starts only the `mhfe.exe` next to it, and stops when
  it cannot change to its folder, instead of starting another one found on the path.

## Fixed

- **Rust library:** `find_addresses_until` with a path asks `stopped` before it derives that
  address too, and `AddressSearch::new` describes Dash Platform's roots beside others with a
  pattern of their own, where it used to stop the program, and counts the addresses as the search
  derives them.
- **Rust library:** `PasswordReview::typed_word` takes the place of a repair and gives `None` where
  the review offers none, where a repair of another review could stop the program; a `Rekey`
  refuses the recovery and the confirmed phrase of another one with `INVALID_REQUEST`.
- **`mhfe serve` and the Python launcher** answer HEAD without a body for an error too, write the
  page without copying it for each request, and read malformed requests and an oversized checksum
  file alike.
- **Windows:** without a standard input, reading it ends as at the end of the input.
- **Browser package:** `onNoLength` refuses the wallet check with a `TypeError`, as the guide says.

## Builds

- **mhfe-core moves to 0.3.0, from crates.io**: it takes the protection of secrets and the isolation
  from secret-protection-core 0.2.0, and the repair words' code from reed-solomon-core 0.2.0. Cards
  and repairs are unchanged.
- **The macOS archives are reproducible too.** Zig links them in the same Docker build as the
  other four, without Apple's SDK, so all six archives can be rebuilt byte for byte and compared
  with the published ones. The release workflow then runs the self-test and the terminal suite of
  both macOS programs on a Mac.
- **Fuzz targets read what a person types**: addresses, derivation paths and fingerprints; phrases,
  containers and repair cards; passwords and dice rolls. The release runs each for 90 seconds, and
  the RustSec check reads their lockfile too.
- **CI runs the tests on ARM64 Linux, on Intel macOS and on Windows with the GNU toolchain**,
  those of the released programs, as well as with MSVC.
- **The release draft is made without the repository's code.** The canonical job hands the notes
  on as an artifact; the attestation job may sign but not write, and only the job that creates
  the draft with `gh` may write. Neither checks out the repository. Every job that takes the
  archives checks them first against the canonical job's `SHA256SUMS`, which is the release's
  own, and the draft holds exactly the archives it lists. `scripts/package-release.sh` lists in
  `SHA256SUMS` only the archives it made, not others left in its folder.
- **Ctrl+C, SIGTERM and a closed terminal** are handled by MHFE itself on Linux and macOS, as
  before; the `ctrlc` crate stays for Windows only, and with it six crates leave the Linux and
  macOS programs.

## Documents

- docs/CLI.md checks an archive's attestation against the release workflow and the release's
  tag, and docs/RELEASING.md against the tag's commit too, beside the tag's and the checksums'
  signatures.
- Every command in the README and in docs/CLI.md has examples, and the README describes an offline
  live system as the recommended way to work. The two container formats are called by what they are,
  24-word and same-length, beside their suite names.
