# Next release notes — draft

Record user-visible changes here as they are made. Before tagging, move them into
`docs/releases/v<version>.md`: the release workflow attaches that file as the text of the draft
release. Without it the canonical job fails before its build and no draft is made, while the macOS
builds and the CI checks of the same run go on until they end or are cancelled.

## Changed

- **mhfe-core.** The cipher, the password rules, the optional profiles, native Argon2 and the
  protections of secrets now come from the crate mhfe-core 0.1.0. Containers, recovered phrases,
  repair words and check words stay byte for byte the same.
- **Isolation on every system.** Every command but `serve` now enters mhfe-core's isolation before
  it reads anything. On Linux the filter also refuses every change to files, calls on other
  processes and every `ioctl` but the terminal's. macOS closes the network with a sandbox and
  refuses debuggers. On Windows a command runs at low integrity, which refuses most file writes,
  programs of the same user are kept out of the process and its threads, and error reports leave
  out the heap; the network stays open, and a command's summary warns of that. The summary's
  Isolation line says what holds on each system. Core dumps that cannot be turned off no longer
  stop a command on Windows, which has no such setting: the self-test says what its error reports
  hold.
- **Secrets in memory.** On Linux on x86-64 and AArch64 secrets lie in the kernel's secret memory
  where it is offered, which no other process reads directly, root included, and the computer
  cannot hibernate while it exists. Windows now locks them too. The BIP39 seed and the BIP32 keys,
  each round's Argon2 key, salt and mask and the lines of a frame are now locked as well. The
  Argon2 work area is locked where the limit on locked memory holds all of it.
- **The start menu runs each command as a process of its own.** A command from the menu is isolated
  and runs its checks at start as a typed one does, on Linux with its own network namespace. The
  password entry is the hidden `mhfe password --repeat`. Ctrl+C ends the command and the menu, while
  Ctrl+D at a secret's prompt now ends the command alone, as Escape and q do, and the menu comes
  back. A command that crashed or was killed no longer takes the menu with it: the menu restores
  the terminal, leaves the private screen and says "The command crashed or was killed." The menu
  and `mhfe serve` hold no secret, and no longer forbid core dumps or make themselves non-dumpable.
- **A new phrase with the wallet check takes minutes.** `mhfe new` draws it on one thread, one trial
  after another, as the specification's proof requires, in about a minute and a half on a current
  computer and now and then several times that, where every processor core used to take seconds. Its
  summary no longer has the "Drawn" record, as the proof covers a draw that reveals neither the
  number of its trials nor its duration; the count stays on the step's screen.
- **Fewer checks on your computer.** Argon2's RFC 9106 vector, its runs on each copy of its core and
  on one thread, the wipe of its work area and the scan of every Unicode character in the full
  self-test are now tests of mhfe-core and no longer run at start or in `mhfe self-test`. A new
  phrase and new repair words are no longer read back after they are made.
- **`mhfe test-vectors` is gone.** The test vectors and their generator live in the specification's
  repository alone.
- **Argon2 failures.** A failure of the native Argon2 code now reads "the reference code returned
  error N", as in the browser; its code stays `ARGON2_FAILED`.
- **Standard input and output without the standard library's buffers.** Secrets typed at the
  terminal, a script's answers on standard input and everything printed on standard output pass
  straight between the operating system and the program's own buffers, which are locked and wiped,
  instead of through the standard library's buffers, which keep their last contents for as long as
  the tool runs. What was typed at the terminal and not read when a hidden prompt or a list ends is
  discarded, so the rest of a paste never reaches the next answer or the shell. A script's answer
  that is not UTF-8 is now refused with exit code 2, as one typed at the terminal is. On Windows,
  Ctrl+Z is now kept as a character at every prompt, as on Linux and macOS; the standard library
  ended a typed answer at it or dropped it. A result that cannot be written, for example to a full
  disk, now ends the tool with exit code 1 and the reason, instead of a panic.
- **A check names every length that matches.** When the built-in check of several lengths passes,
  by chance, `mhfe check` lists each of them, on standard error for a script, and the browser
  package gives the others in `evidence.otherLengths`, as specification 0.7.0 requires. Only the
  first was named before.

## Fixed

- **A key pressed early no longer clears a private screen.** Keys pressed during the work before a
  private screen, such as a long draw or a recovery, are discarded, so that none ends the wait for
  Enter or Escape before the phrase on it has been read.
- **Keys during the checks at start.** Ctrl+C, Ctrl+\ and Ctrl+Z now end a command in its checks at
  start too; Ctrl+Z used to stop it there.

## Browser package

- **A new phrase in one worker.** `drawPhrase()` draws a phrase with the wallet check in one worker,
  one trial after another, as the specification's proof requires, which takes minutes. Its `workers`
  option and the `workers` field of its result are gone.
- **Argon2's stack.** The Argon2 builds clear the stack behind the reference code after every
  segment and every call, the stacks of the lane threads included. They export
  `mhfe_argon2id_hash_raw` for it and run only in a worker.
- **`modules.json`** lists the modules in byte order, and so does the README's list of SHA-256.

## Library

- **Free functions.** The operations moved from methods of `Mhfe` to functions that take it first:
  `encrypt`, `decrypt`, `decrypt_as`, `check`, `recover_for_check`, `recover_for_check_in_stages`,
  `recover_confirmed` and `derive_wallet`. `mhfe_core::Mhfe::with_engine(work, reserve(work)?)`
  replaces `Mhfe::new`, and `SelfTest::run` takes the settings and the engine.
- **The core's types.** `Mhfe`, `Password`, `Suite`, `WorkFactor`, `Phrase`, `Argon2Engine` and
  `NativeArgon2` are mhfe-core's, and `repair_words` and `repair` give its `Card` and `Repaired`.
  What only mhfe needs on them is free functions, such as `memory_bytes` and `estimated_seconds`.
- **Gone:** `engine::NativeEngine` and the written-key guard around it, `engine::LANES` and
  `Argon2Cost`, `wallet_check::passes`, `verify_entropy`, `draw_on_every_core`, `SharedDrawReport`
  and `PhraseDraw::try_draws`, `memory::LockedBytes` and `LockedPages`,
  `RecoveredPhrase::into_phrase`, `mhfe::vectors` and `other_detected_lengths`.
- **Replaced:** `Mhfe::encrypt_unchecked`, `check_new_container` and `NewContainer` by the
  `on_unchecked` callback of `encrypt`; `phrase_from_entropy` by `Phrase::from_entropy`;
  `eff::EffList` and `check_word::check_index` by `EFF_WORDS` and `check_word` in
  `mhfe_core::password_check`; `repair::REPAIR_WORD_COUNTS` by `Card::SIZES`; `SUITE_ID` and
  `SAME_LENGTH_SUITE_ID` by `Suite::id()`; `MAX_PIM` and `MAX_MEMORY_LEVEL` by the same names on
  `WorkFactor`; `MAX_PASSWORD_BYTES` by `Password::MAX_BYTES`.

## Build, tests and release

- **The vectors come from the specification.** `tests/fixtures/` is gone: the program and the tests
  read them through the submodule `tests/spec`, at the specification's tag v0.7.0, so a clone needs
  `--recurse-submodules`. The Test vectors workflow and mhfe's independent Python checkers went with
  them, and the check of the terminal cell table moved to `ci.yml`.
- **`build.rs` is gone.** mhfe-core compiles the native C code. `vendor/phc-winner-argon2` stays for
  the browser builds, and `BUILD-INFO.txt` names mhfe-core's version in a native archive and the
  vendored commit in the browser package.
