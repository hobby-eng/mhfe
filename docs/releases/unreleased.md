# Next release notes — draft

Record user-visible changes here as they are made. Before tagging, move them into
`docs/releases/v<version>.md`: the release workflow attaches that file as the text of the draft
release. Without it the canonical job fails before its build and no draft is made, while the macOS
builds and the CI checks of the same run, and `vectors.yml` for the tag, go on until they end or
are cancelled.

## New

- `mhfe new --wallet-check yes|no` and `--choose-word yes|no`,
  `mhfe check --passphrase-used yes|no` and `--wallet-check`, and
  `mhfe encrypt --same-length no` answer those questions beforehand.
- `--coin` and `--path` also reach address confirmation in `rekey` and both wallet references
  used to find missing container words.
- The browser client exposes `keepOldContainer()`. Rekey results name their replacement
  `rehearsal`; owner confirmations state `rehearsalNeedsPassphrase` and accept `{ passphrase }`
  only where it is needed. `evidence.passed` lists the recovered phrase's passing own checks.
- Retention lists distinguish `passphraseIfAny` and `wordCount`; keep the latter apart from the
  container when another length would pass automatic detection.

## Changed

- Native Linux Argon2 work areas require successful whole-page dump exclusion and bounded
  `/proc/self/smaps` readback before use. Direct allocation failure returns the new
  `EngineError::MemoryProtection` / `MEMORY_PROTECTION_FAILED` refusal. Startup and full checks
  retain that cause in a failed component; their enclosing `SELF_CHECK_FAILED` contract remains.
  Linux library hosts must permit reading that metadata. The logical Argon2 extent and
  cryptographic parameters are unchanged.
- Rust `Bip39Passphrase::read` checks the raw 1,024-byte passphrase bound without normalization.
  Interactive CLI prompts retry excessive passphrases and malformed visible lines while retaining
  earlier answers; scripted input remains fail-fast.
- Browser word hints and each chosen/excluded word value enforce the shared 8,192-byte raw input bound
  before scanning or copying. Browser methods retain string and `Uint8Array` support without
  consuming caller storage. Rust `WordHintError` and `WishError` add a typed `Text` cause.
- Browser startup reports must account for every requested check using current results or the
  verified cache captured before the run. Incomplete reports cannot admit work or populate the
  cache. Raw self-check IDs describe their requested tier; full Argon2 checks retain separate
  known answers for each build as well as the larger memory checks.
- Original/container phrase readers enforce the shared 8,192 raw UTF-8 byte limit before scanning,
  including whitespace, with `INVALID_REQUEST`. Rust `PhraseError` adds the `Text` cause variant;
  exhaustive matches must handle it. Password and passphrase encoding limits stay independent.
  Browser core/repair/wallet parameters expose `maxInputTextBytes`; their phrase/container
  transports and the exported `requireInputText` / `InputTextBoundary` admit text before copying.
- Search candidate values, selected words, match indices and checksum scratch use wiping owners.
  Two missing words have a flat candidate-value pool bounded to 16 MiB. Rust `Found::words()` now
  returns an exact-size borrowed iterator. Encryption/rekey/repair/search/password JSON serializes borrowed owner
  views into final-size wiping staging; JavaScript methods and result fields stay the same.
- Repair arithmetic, changed-word positions, subset scratch and terminal card rows use wiping
  owners allocated at their bounded sizes. Card output and correction reporting avoid ordinary
  temporary word strings; public repair results and terminal layout remain the same.
- Rust container inspection and card extraction return typed `Result`s and share the 8,192-byte
  input limit with repair and dice text. Counts are checked before collection, card text is copied
  at its exact final size, and indexed word/position buffers wipe on drop. Existing browser JSON
  fields stay the same; oversized input fails with `INVALID_REQUEST`.
- Rekey recovery and confirmation tokens are bound to the canonical source container, normalized
  old password and old work settings. Other origins fail with `INVALID_REQUEST` before callbacks
  or work; separately constructed equivalent rekeys remain compatible. Tokens retain a wiping
  credential owner until the last token drops. Rust adds `RekeyError::OriginMismatch`; browser
  methods and JSON fields are unchanged.
- Rust `EffList::word`, `different_dice_words`, `PasswordReview::of` and `Strength::of` return
  typed `Result`s. Text utilities refuse raw UTF-8 input above 8,192 bytes before owned copies;
  empty and nonprofile input remain accepted by review/estimation. Repairs own and wipe their
  selected word, position and typed range; `Repair::word()` borrows from the repair, and Debug
  withholds all of them. Browser JSON fields are unchanged.
- `Millibits::get()` and `PasswordRecipe::millibits()` return `u128`, so every host-sized draw
  count has an exact strength without overflow. Existing recipe strengths and display text agree.
- `PasswordReview::typed_word(&repair)` returns a `Result`. Repairs retain their review's
  identity when cloned; another review's repair is refused, including for identical text.
- Rust result records have private fields and read accessors. `Phrase::read` and `from_entropy`
  own normalized BIP39 text in a locked, wiping buffer; `into_words` transfers it without a copy.
  Native memory probes, self-check set constructors, password check indexes and vector generation
  are methods of their owners; [the API migration](../API.md) lists the replacements.
- Core browser parameters add `progressStages`, `progressRoundTotals` and `openedWordCount`.
  Error codes and attached self-check reports are readonly properties.
- Coin address rules have one definition per coin. The Rust `Coin::address_forms()` method now
  returns `String`; browser parameter fields, coin order and existing address examples stay the same.
- Rust repair operations are owned by `repair::RepairWordCount`: validate a size with `new`,
  then call `capacity` or `words_of`; `RepairWordCount::repair` reads a damaged card. Random-source
  probes and bounded draws are methods of `random::RandomSampler`. Browser method names and
  payloads are unchanged.
- Rust fingerprints use `wallet::Fingerprint` for parsing, derivation, references and display;
  `ContainerFacts::fingerprint()` is the entry for a container's own fingerprint. Password review
  choices belong to `PasswordReview`, typed-password validation to `Password`, dice parsing to
  `EffList`, and exact random strengths to `new_password::Millibits`. `Address` owns `find` and
  `find_until`; `WordCount` owns built-in-check applicability and `PassphraseReferences` the
  unused-passphrase refusal. Browser payloads are unchanged.
- `wallet_check::WalletCheck::new(passphrase)` borrows the passphrase for criterion, verification
  and repetition checks; its methods replace the free functions. Raw criterion checks still allow
  an empty passphrase; profile verification still requires a nonempty one and 24 words.
- Random providers and sampling return `random::RandomError`, converted into `MhfeError::Random`
  at composed operations. Stable `ErrorCode` values can be read without constructing an error.
  OS failures keep a numeric system code; page-source failures retain the source's identity and
  omit arbitrary thrown text that might contain secrets. Existing error codes are unchanged.
- Independent Rust modules return their own typed errors, with `From` conversions into composed
  `MhfeError` operations and a shared `ErrorIdentity` interface. Error reasons carry typed fields;
  the prior stable codes and browser result schemas remain, with `MEMORY_PROTECTION_FAILED`
  added for a total of 53. Native callers matching flat error
  variants must use the owning error. Progress callbacks return `CancelledError` with their
  existing arguments/order. Self-check failures retain typed reasons and case metadata while
  their browser `detail` remains a string.
- Browser Argon2 startup failures report the affected build and known isolation context without
  retaining factory exception text. Package mismatches remain fatal; only self-checks can fall
  back to the single-threaded build.
- Word counts, format refusals and scalar work-factor data live below cipher execution; their
  root/engine type names remain available. `FormatError` owns format failures and converts to
  the aggregate `MhfeError::Format`. Wallet checks and wallet derivation share the same locked,
  wiping BIP39 seed implementation and `PassphraseError`, independently of address/key code.
- The rehearsal check reports one of the specification's three results: "matches", "does not
  match" or "not verified". "Not verified" is a 24-word reading without an address or fingerprint,
  which a wrong password gives too, or several lengths that pass their built-in checks with none of
  them stated; MHFE lists those lengths. A pass of the 16-bit phrase + passphrase check is reported
  beside the result and no longer counts as a match. `mhfe check --stdin` prints "not verified"
  with the new exit code 5. In the browser package `check()` resolves to `outcome` ("matches",
  "notVerified" or "doesNotMatch") in place of `matches`, `evidence.matchingLengths` lists the
  lengths, and `onNoLength` receives the evidence.
- MHFE is licensed under the MIT license or the Apache License 2.0, at your option
  (`LICENSE-MIT`, `LICENSE-APACHE`); releases up to 0.6.0 remain available under the MIT license.
  Every release archive carries both licence files.
- A command that reads a secret refuses at its start, with the advice to run it in a terminal or
  pass `--stdin`, when its standard input is not a terminal and `--stdin` is not given, instead of
  reading that input as answers.
- `mhfe rekey` refuses an invalid `--new-pim` or `--new-mem`, and a `--confirm` that the stated
  length does not allow, before the old container's recovery instead of after it.
- The start menu offers the fast mode only when the page beside the program is there and matches
  its checksum file; otherwise it says why the fast mode is not offered.
- `mhfe serve` starts with its title line and wraps its lines at 78 columns, and both fast-mode
  launchers always print the page's address, also when a browser was opened. The Python launcher
  writes as the program does: ✓ and "✗ Error:", colours only at a terminal, `NO_COLOR` honoured.
- When a phrase also reads as another length, the note of its word count is to be kept apart from
  the container phrase, like the password.

## Fixed

- Repacking an existing ZIP replaces removed entries rather than retaining them. A failed ZIP
  command leaves the previous archive unchanged.
- Browser methods refuse non-object option containers rather than silently selecting defaults.
  Oversized chosen/excluded-word arrays fail before entry access, transport copies or workers.
- Vector reads and checksum generation refuse nonregular files and vectors above 1 MiB;
  checksum hashing uses fixed scratch space. Temporary vector paths are created exclusively.
  Both fast-mode launchers also refuse final symbolic links to their page or checksum file.
- CLI usage errors withhold supplied values, unknown arguments and subcommands, including every
  line of multiline input. Suggestions name only configured options. A refused selector for
  `test-vectors --only` is not repeated and creates no files or directories.
- Direct hidden-wallet recovery and raw WebAssembly recovery enforce the shared BIP39 passphrase
  byte limit before Argon2 work. Raw rekey options validate repair counts before recovery starts.
- Address searches check cancellation for an explicit path before deriving it, as they do for
  addresses in a scan.
- An outside EFF word index, including an integer that would overflow the weighted sum, is refused
  as `INVALID_REQUEST` before arithmetic. A quick startup refusal guards the same boundary.
- Browser progress refuses negative, fractional and over-total rounds before calling page code.
- Historical audit report assembly retains valid Python around local-only procedure references.
  The audit-record gate parses retained Python harnesses without rerunning their historical work.
- Windows secret buffers use `VirtualLock` with shared-page holder counts. The CLI opts out of
  Windows Error Reporting and restricts process memory access with an `OWNER RIGHTS` DACL;
  startup checks read both policies back. macOS requests `PT_DENY_ATTACH`, and release binaries
  carry the hardened runtime, inspected through `csops`. Unsigned macOS builds report when this
  policy cannot be verified.
- Windows archives carry the pinned MinGW runtime's complete copyright and licence texts, with
  binary/archive checks that reject missing notices.
- macOS release jobs use the runner's existing Python tar/gzip writer rather than installing
  Homebrew packages during an attested build, and record packing/compiler/SDK versions.
- Windows standard input bypasses the standard library's persistent read-ahead buffer, as Unix
  input already does; the owned pending buffer is wiped as it is consumed, including UTF-16
  surrogate pairs converted from console input.
- Warn when the swap inventory cannot be read or its protection cannot be verified, including the
  Windows pagefile, instead of treating it as confirmed empty.
- Refuse generated container-password output when a private screen cannot be established, including
  failed Windows VT activation; check the acquired screen again immediately before display.
- A zram swap device with a writeback device is judged by that device, so that an unencrypted one
  gives the swap warning.
- The word hints of a phrase or password no longer copy the matching words into strings that are
  not wiped.
- A result that cannot be written to standard output, on a closed pipe or a full disk, ends with
  "Input or output failed" and exit code 1, never as a success or a panic.
- Keys typed during the start or during long work no longer answer the next question or close a
  screen that shows a secret once.
- At `TERM=dumb` the word prompts write no cursor-control sequences and no hint rows.
- Interactive result display is refused before input or work without a private screen; explicit
  redirection and the `--stdin` export protocol remain supported.
- Refused secret lines can be retyped without losing earlier work; an over-long line is discarded
  through Enter, even if its paste pauses. Invalid UTF-8 on standard input has exit code 2.
- Accepted abbreviated, differently cased or ambiguous-prefix words are read back in full. Secret
  words are shown only on the private input screen; the next question waits for confirmation.
- Both localhost launchers report SIGINT, SIGTERM and SIGHUP consistently with exit code 130;
  a page must have a lower-case `.html` suffix, with a separate refusal for other names.
- Encrypt's `--repair-words` adds its repair words as a second line of standard output.
  Decrypt's and check's `--repair` consume a repair-word line of standard input after the container.
  Their help names both, and `mhfe serve` explains the checksum file's two-space format.
- The startup self-checks no longer wait a fixed 0.2 s; they take about 0.08 s.
- The Python fast-mode launcher keeps serving after a connection fails, as `mhfe serve` does.

## Browser package

- Secret byte owners collect, transfer and wipe request buffers at any nesting depth. Cancellation
  also wipes copies held while WebAssembly compilation is pending; JavaScript erasure remains
  best effort.
- Malformed worker requests, answers and callback payloads are refused as `PACKAGE_MISMATCH`
  before page callbacks run.
- `keepOldContainer()` describes valid old settings above the browser's memory limit without
  applying the limit for operations that allocate memory.
- A BIP39 passphrase given where an operation does not use it, inside the reference of `check()`,
  `searchDecoy()` or an address or fingerprint `rekey()`, or beside `{ builtInCheck: true }`, is
  refused with a `TypeError` instead of being dropped.
- The early refusals of the PIM, the memory level, the word count and the repair-word count use
  the library's sentences.
- A WebAssembly trap inside a hidden-wallet session, a rekey recovery or a check session rejects
  with `INTERNAL_ERROR`, "The WebAssembly stopped", instead of a wasm-bindgen ownership error.
- `MhfeRepair`'s startup self-check covers the master key fingerprint that every repair computes,
  and `MhfePasswords` built alone carries only the password cases of its self-check.
- The guide documents worker-termination and JavaScript-string erasure limits, pending secret
  sessions and the host page's offline, network, verification and rehearsal responsibilities.

## Library

- A sealed result drops the original creation-check state before returning. Hidden-wallet sessions
  keep container text in a locked, wiping owner; repair results and changes wipe their owned text
  and omit it from `Debug`, including clones. These changes do not erase copies held by callers.
- Rehearsal self-checks compare all evidence, including the wallet check, every passed check and
  the follow-up decision. Old-container keep lists and replacement rehearsal references have
  independent expected values and damaged-value controls.
- Rekey self-check controls reach the intended comparison and refusal branches and assert their
  exact failures. Address search descriptions cover every supported coin and address purpose;
  the full component check searches all published address vectors within small bounds.
- The published-round table generator uses Node.js and preserves every table value. Release
  wrappers share Cargo metadata parsing and archive licence validation; standalone launcher
  parity covers all shared messages, exits and digest length.
- Repeated rekey confirmations and rehearsal answers use library rules. `Rekey::confirm_again`
  validates the owner's length against the preceding refusal; `owner_states` replaces public
  `set_length`. A rehearsal follow-up refuses detection again and the wallet check through
  `RecoveredForCheck::compare_after_detection`, shared by the CLI and browser binding.
- CLI encryption refuses `--same-length` for a 24-word phrase before reading passwords, as the
  library and browser do, instead of silently selecting the other suite.
- Terminal screen switches, clears and cursor redraws share a bounded raw writer. A failed
  switch stops the command before private input or output; only a completed switch sets the
  private-screen flag. Cleanup remains bounded, and an uncertain screen mode refuses subsequent
  private operations in the same process.
- CLI progress labels use the library's reported stage without renumbering rekey or self-test
  rounds. Test-only vector estimates use the selected work factor and operation's round count;
  benchmark records ask the engine for its core and thread description.
- `NewContainer`, `CheckEvidence` and `search::Found` expose read-only methods in place of public
  fields. This requires source changes for callers that accessed those fields directly.
- `repair::CardWords` owns normalized as-typed card text in locked memory, exposes its words and
  count, and wipes it when dropped; the internal card parser is private.
- `CheckOutcome::NotVerified` adds an outcome, a breaking change for exhaustive matches.
- New or newly exported APIs include `ContainerFacts::fingerprint`, `GroupedCount::new(count)`
  (formatted through `Display`),
  `PassphraseReferences::refuse_unused`, `PassedCheck`, `PassphraseReferences`, `Settings`,
  `ReplacementRehearsal`, `ConfirmedPhrase`'s rehearsal methods, `Keep::old_container` and
  `self_check::process`. `ContainerFacts::require_wallet_check` offers the same applicability
  refusal to each front end.
- Coin identifiers use exact lower-case spelling without surrounding spaces. `InvalidCoin`
  is now a unit error variant whose one Display implementation supplies its full sentence.
- `memory::LockedPages` and `LockedText::from_locked` are internal. Public callers construct
  locked text through its buffer owner, so a guard for another allocation cannot claim it is locked.
- Locked-buffer builders verify the allocation address and capacity before returning a fill's
  result. A replacement allocation of the same capacity and a failed fill cannot bypass the guard.

## Build, tests and release

- Browser diagnostics include the complete core parameter schema. Native lock expectations cover
  Windows and Unix. The macOS attachment probe first requires an attachable public control, then
  tests a protected child; unavailable controls fail with an explicit unverified result.
- The live audit-record gate discovers both companions, refuses malformed or duplicate-key JSON,
  and compares filename, audit identity, JSON date and the stated UTC completion metadata.
- Browser source files are split by operation and runtime responsibility. A checked source join
  preserves the package's existing file paths and public exports; no file-length lint exceptions
  remain in the browser sources.
- Update the pinned Rust dependencies `cc` to 1.8.0 and `serde_json` to 1.0.154.
- Fast gates check Python widths and the inventory of CLI questions and scoped options. Terminal
  cases cover explicit scan gaps, address paths, checked passwords, repair, passphrase answers,
  generated passwords, memory settings and test-tool selection before full-size Argon2 work.
- Self-checks and unit tests share their public inputs and independent tables; all distinct repair
  cases remain covered. The published-vector self-test reports its own total round count.
- Browser self-check timings are reported as information rather than unconditional passing
  checks. Positive missing-word searches and old-backup descriptions have class/worker coverage.
- The standard-output check follows stdout aliases and checks production code after test-only
  items; the Rust rules scanner ignores braces in comments and literals.
- The Windows zip's permission bits no longer depend on the umask of the checkout, and
  `THIRD_PARTY_NOTICES.md` covers the Rust standard library and the crates it is built from.
- `BUILD-INFO.txt` reads the vendored Argon2 commit and the Emscripten version from their sources,
  and a check keeps every copy of the pinned versions equal to its source.
- The vendored Argon2 gate refuses an added file; the lexical network tripwire shares its
  patterns and checks its two counted Worker exceptions. It does not prove arbitrary code offline.
- Release README files include their mascot asset and have their relative links checked before
  packing. Release checksum lists name exactly the archives written by that run.
