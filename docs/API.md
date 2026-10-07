# MHFE implementation API

This describes the Rust library and the browser package of suite `MHFE-BIP39-256-EXPERIMENTAL-3`,
the 24-word containers, and suite `MHFE-BIP39-LP-EXPERIMENTAL-4`, the containers of the same length
as a 12- to 21-word original. The command-line tool is described in the [README](../README.md).

## Rust library

```rust
use mhfe::{CheckOutcome, Mhfe, Password, PhraseLength, Recovery, Reference, Suite, WorkFactor};

let work = WorkFactor::new(0, 0)?;            // PIM 0..=1023, memory level 0..=21
let password = Password::new("...")?;        // NFKD with Unicode 17.0.0, 1 to 1024 bytes
let mut mhfe = Mhfe::new(work)?;              // checks free memory, reserves the Argon2 work area

// Suite::TwentyFourWords is the default; Suite::SameLength only on the user's own choice.
let container = mhfe.encrypt(original, &password, Suite::TwentyFourWords, &mut |round, rounds| {
    println!("Round {round}/{rounds}");       // return Err(MhfeError::Cancelled) to stop
    Ok(())
})?;

match mhfe.decrypt(&container, &password, PhraseLength::Detect, &mut |_, _| Ok(()))? {
    Recovery::Phrase(phrase) => { /* phrase.words, phrase.verified, phrase.phrase, phrase.suite */ }
    Recovery::Ambiguous(candidates) => { /* show every candidate; the last one is 24 words */ }
}

let outcome: CheckOutcome = mhfe.check(&container, &password, &reference, &mut |_, _| Ok(()))?;
```

- `WorkFactor` holds the two settings and computes the Argon2 cost with integers only:
  `memory_kib()`, `passes()`, `estimated_seconds()`.
- `Mhfe::new` refuses a memory level the build cannot address
  (`MhfeError::MemoryLevelNotSupportedHere`: a native build is always 64-bit and supports every
  level, the browser build level 0 only, see `engine::HIGHEST_MEMORY_LEVEL`) or the computer cannot
  provide (`MhfeError::NotEnoughMemory`), and reserves the work area once; every round of every
  operation reuses it. The engine is the vendored reference C code (`engine::NativeEngine`). Like
  the browser's engine, it fills each round's key with a marker before Argon2 runs and refuses a key
  left so or set to zeros (`ARGON2_FAILED`). `Mhfe::engine()` gives the engine.
  `engine::check_can_run` makes the same checks without allocating, so a program can refuse at once
  and reserve the memory only after the password has been encoded, the order the specification gives
  for creating a container.
- `Password::new` rejects, never cleans or truncates: a control character (General_Category Cc, such
  as NUL, TAB or a line break), U+2028 or U+2029, any code point that Unicode 17.0.0 does not
  assign, an empty result and more than 1024 bytes after normalization. Private Use characters are
  allowed. `Password::from_utf8` does the same for bytes.
- `encrypt` accepts an English phrase of 12 to 24 words in any letter case and spacing, and four or
  more leading letters per word. It refuses the practically impossible case that the container
  equals the original (`MhfeError::FixedPoint`). Before it returns the container it decrypts its
  words again and compares the result with the original, so it runs 24 rounds, twice the time of a
  recovery; a difference, which only a hardware or memory fault could cause, discards the container
  with `MhfeError::VerificationFailed`.
- `Suite` selects the container. `Suite::TwentyFourWords`, the default (suite 3), turns every
  original into 24 words. `Suite::SameLength` (suite 4) turns a 12-, 15-, 18- or 21-word original
  into a container of the same length; it has no built-in check, so a wrong password gives another
  valid phrase, the container shows the original's length, and its BIP39 checksum of 4 to 7 bits
  catches fewer copying mistakes. The specification allows it only when the user has chosen it
  after the application has shown these consequences, and asks the application to show
  `Suite::id()`, the suite identifier, after creating a container. A 24-word original has no
  same-length form (`MhfeError::SameLengthNeedsShortPhrase`, before any Argon2 work).
- `encrypt` is `encrypt_unchecked` (rounds 1 to 12, returns a `NewContainer`) followed by
  `check_new_container` (rounds 13 to 24). A program that shows the container to a person between
  the two must mark it as not yet verified and report the outcome of the check, as the specification
  requires; a result for another program should come from `encrypt`.
- The progress callback receives the round that starts and the number of rounds: 1 to 24 for
  `encrypt`, 1 to 12 for `decrypt` and `check`. An error it returns stops the operation before the
  next round.
- `decrypt` takes the suite from the container's word count: 24 words are suite 3, 12 to 21 words
  suite 4. A suite 4 container gives one phrase of its own length, never verified, with
  `RecoveredPhrase::suite` set to `Suite::SameLength`. `decrypt_as` takes a suite the user selected
  as well; a container of the other suite's word count is then refused before any Argon2 work.
- For a 24-word container, `decrypt` with `PhraseLength::Detect` tests the 12-, 15-, 18- and 21-word layouts. One match gives
  a verified phrase; no match gives the 24-word reading, not verified; several matches give
  `Recovery::Ambiguous` with every matching candidate and the unverified 24-word reading.
  `PhraseLength::Words(WordCount::new(n)?)` selects the length: `WordCount::new` accepts only 12,
  15, 18, 21 and 24; a short length must pass its check (`MhfeError::VerifierMismatch` otherwise),
  24 words are always accepted. A chosen length `n` admits only a 24-word container or a same-length
  container of exactly `n` words; any other container is refused before any Argon2 work
  (`MhfeError::LengthChoiceNotApplicable`), as the recovery table of the specification requires.
- `check` compares the recovery with a `Reference`: `BuiltInCheck { words }`, with a `WordCount`
  of 12 to 21, for a short original in a 24-word container (a same-length container has none:
  `MhfeError::NoBuiltInCheck`), `Address { address, passphrase, path, limits }` for a
  receiving address (the strong check), read with `wallet::Address::parse(coin, text)` for one of
  the twelve `wallet::Coin`s, whose standard paths `Address::search_roots` and
  `Address::hardened_chains` describe (BIP44-style, or DIP17 for a Dash Platform payment
  address), or `Fingerprint { fingerprint, passphrase }` for the BIP32
  master key fingerprint. It returns a `CheckOutcome`: `Matches { path }` or `DoesNotMatch`, where
  `path` is the derivation path at which a matched address was found (`None` for the other
  references). No part of the recovered phrase comes out. `Reference::passphrase()` gives the BIP39
  passphrase a reference is compared with, empty when it is compared with the wallet without one,
  and `None` for `BuiltInCheck`, which says nothing about a passphrase.
- `recover_confirmed(container, password, words, confirmation, on_progress)` recovers a phrase to
  encrypt it again under a new password or settings, and returns it only once it is confirmed (the
  re-encryption guard). A 12- to 21-word original of a 24-word container always passes its
  built-in check at the stated length `words`. A 24-word original or a same-length container needs
  `Confirmation::Wallet(reference)`, an address or a fingerprint (`REFERENCE_REQUIRED` without one,
  `REFERENCE_MISMATCH` when it does not match), or `Confirmation::Owner`: the caller then shows the
  phrase and goes on only if the owner confirms it against their backup. Encrypting under the old
  password and comparing proves nothing, so it is not offered.
- `derive_wallet(container, password, passphrase, on_progress)` gives the hidden wallet that
  `password` opens on a 24-word container, read as 24 words, unverified (a hidden wallet behind an
  honest disclosure). A password whose reading passes the built-in check of a 12- to 21-word
  phrase, or the wallet check with the main wallet's `passphrase` or without a passphrase, is
  refused (`HIDDEN_WALLET_PASSES_CHECK`). Running the published vectors at full cost on the
  computer, as `mhfe self-test --vectors` and the browser package's `selfTest()` do, before such a
  wallet is funded guards against a build or computer that computes MHFE wrongly and would show a
  wallet no correct program finds again.
- `wallet_check` (a draft of the profile MHFE-WALLET-CHECK-SEED-1). The criterion: a phrase passes
  when `SHA-256("MHFE-WALLET-CHECK-SEED-1" || BE32(ENT) || seed)` starts with 16 zero bits, its
  first two bytes being zero. The tag is 24 ASCII bytes with no NUL; `BE32(ENT)` is the entropy's
  length in bits as a 4-byte big-endian number; `seed` is the raw 64-byte BIP39 seed of the
  canonical English phrase (lower case, one space between words) with the passphrase in NFKD. A
  pass is statistical evidence: a wrong password or passphrase passes once in about 65,536, and
  drawing the phrase this way leaves about 240 of its 256 bits.
  - The library offers the check for a 24-word phrase, 256 bits of entropy, with a BIP39
    passphrase that is not empty, one rule for every front end: without a passphrase the seed is a
    function of the phrase alone, and anyone who saw the phrase could test it.
    `require_passphrase(passphrase)` refuses an empty passphrase (`WALLET_CHECK_NEEDS_PASSPHRASE`),
    for a front end to ask before anything else. `verify(phrase, passphrase)` tests a recovered
    phrase: an empty passphrase is refused first, then a phrase of another length than 24 words
    (`INVALID_WORD_COUNT`). `verify_entropy(entropy, passphrase)` does the same for the entropy of
    a 24-word phrase, 32 bytes (`INVALID_WORD_COUNT`, by the words it would have, otherwise).
  - `Reference::WalletCheck { passphrase }` lets `check` test it on a 24-word container, against
    its 24-word reading only, never a shorter one. Before any Argon2 work a same-length container
    is refused (`NO_WALLET_CHECK`) and then an empty passphrase (`WALLET_CHECK_NEEDS_PASSPHRASE`).
    It never confirms a recovery to encrypt again (see `recover_confirmed` and `rekey::Rekey`).
  - `passes(entropy, passphrase)` and `phrase_passes(phrase, passphrase)` compute the bare criterion
    for an entropy of any length BIP39 takes and any passphrase, the empty one included, with
    `BE32(ENT)` of that length. `RecoveredPhrase::passes_wallet_check_without_passphrase()`, which
    reports a phrase that another program made in that form, and the guard of hidden wallets use
    them; a program that checks a recovery uses `verify` or `verify_entropy`.
  - `PhraseDraw` draws a new 24-word phrase: `PhraseDraw::unchecked()`, or
    `PhraseDraw::with_check(passphrase)`, which refuses an empty passphrase
    (`WALLET_CHECK_NEEDS_PASSPHRASE`), then `draw(source, on_draws)`. Natively
    `draw_on_every_core(new_source, on_draws)` draws with the check on one thread per processor
    core, each with its own source from `new_source`, and without the check on the calling thread.
    `try_draws(source, count)` is the step for a program that runs its own threads or workers. The
    first passing entropy of any of them is taken, which leaves every passing entropy equally
    likely; `on_draws` hears the draws, of every thread together, every 1,024
    (`wallet_check::DRAW_REPORT_INTERVAL`) and stops the draw with an error, as does an error of any
    thread. `draw` and `draw_on_every_core` probe every source with `random::check_source` first and
    read the phrase they found back, which must give the same entropy and, with the check, pass it
    again (`INTERNAL_ERROR` otherwise); `try_draws` does neither, so a program that calls it probes
    each source with `check_source` first. `is_checked()` says whether the draw has the check. A
    `NewPhrase` holds the phrase in locked memory (`phrase()`) and says whether it was drawn with
    the check (`checked()`).
  - The public vectors of the criterion: the entropy of 24 zero bytes followed by the big-endian
    64-bit number 76,562 passes with the passphrase `TREZOR`, and with 98,918 it passes without a
    passphrase, which `passes` computes and the check itself refuses.
- `repair` (the optional profile MHFE-REPAIR-1 of the specification):
  `repair_words(container, count)` gives 2, 4, 6 or 8 repair words for a container, the parity of
  a Reed–Solomon code over GF(2^11) whose symbols are the numbers of the BIP39 words, and
  `repair(plate, card)` repairs a plate from its words as read and its repair words as read, `?` or
  a word outside the list marking an unreadable one. It repairs `2e + s <= k` damaged words, `e`
  wrong and `s` unreadable, without the password, and returns the container with the positions it
  repaired (`Repaired`). When no repair within that bound passes the BIP39 checksum it gives
  `REPAIR_NOT_POSSIBLE`. More damage, or a card of another plate, usually ends so, but can also
  give another container that passes the checksum: a repair does not show that the card belongs to
  the plate or that the container is the original; only a rehearsal against the wallet does.
  `repair_words` reads its card back before it gives it out: the plate and the card must form a
  codeword, and the card must restore as many of the plate's first words as it has words when they
  are unreadable (`INTERNAL_ERROR` otherwise). The module documentation gives the code byte for
  byte.
- `ContainerFacts::read(container)` and `OriginalFacts::read(phrase)` read words before any work
  and say what follows from them: a container's suite, the lengths its phrase can have, which of
  them has a built-in check, what confirms a recovery of each (`confirmation_needed`), whether
  hidden wallets and the wallet check apply, and its own master key fingerprint; an original's
  word count, the other lengths detection would also accept, and the containers it can go into,
  each with how often a miscopied word passes its checksum (`ContainerChoice`).
  `BUILT_IN_CHECK_WORD_COUNTS` and `WORD_COUNTS` are the lengths.
- `operation` holds what several front ends share about long operations. `Stage` (`Recover`,
  `Encrypt`, `Check`, `Compare`) and `StageCallback` report the stage, the round of the whole
  operation and its rounds: 24 for an encryption, 36 for a rekey; an error stops it.
  `Encryption::new(original, suite, repair_word_count)` refuses everything it can before any
  Argon2 work, and `run(mhfe, original, password, progress, on_unverified)` encrypts, makes the
  repair words, hands the unchecked container to `on_unverified` and checks it, returning a
  `Sealed` container: its words, suite, repair words, `built_in_check()`, `other_lengths()` and
  `keep(work, passphrase)`, a `Keep` list of what the owner keeps (`KeepItem`). `passphrase` is
  whether the wallet has a BIP39 passphrase; MHFE encrypts only the phrase, so with `true` the list
  names it (`KeepItem::Passphrase`), after the container's words and the password and before the
  repair words, a PIM or memory level that is not the default, and the word count.
  `Mhfe::check_in_stages` is `check` with the stages "recover" and "compare".
- `rekey::Rekey` holds the re-encryption guard:
  `Rekey::new(container, words, old_password, old_work, other_wallets_moved)` refuses before any
  Argon2 work a rekey whose owner did not confirm that the wallets of other passwords are safe
  (`OTHER_WALLETS_NOT_CONFIRMED`) or whose length the container cannot have; `check_new` refuses a
  new password and settings that give the old container again (`NEW_PASSWORD_SAME_AS_OLD`).
  `recover(mhfe, confirmation, wallet_has_passphrase, progress)` runs only at the old settings and
  takes only `Confirmation::BuiltInCheck` where the length has a built-in check (`INVALID_REQUEST`
  otherwise). Where it has none, the built-in check, and a `Reference::BuiltInCheck` or
  `Reference::WalletCheck` in `Confirmation::Wallet`, are refused with `REFERENCE_REQUIRED` first,
  before the answer below is judged. `wallet_has_passphrase` is the caller's answer whether the
  wallet has a BIP39 passphrase, for the new container's keep list. Only a `Confirmation::Wallet`
  reference compared with a passphrase that is not empty shows that the wallet has one: the answer
  may then be `None`, and `Some(false)` is refused (`INVALID_REQUEST`, "stated otherwise than the
  reference shows"). Everywhere else it must be stated, and `None` is refused (`INVALID_REQUEST`,
  "say whether the wallet has a BIP39 passphrase"): the built-in check and `Confirmation::Owner`
  show nothing of a passphrase, and a reference with an empty passphrase matches the phrase's
  wallet without one, which proves nothing about funds under a passphrase; there `Some(true)` is
  taken and the keep list names the passphrase. All these refusals come before any Argon2 work.
  `recover` returns a `ConfirmedPhrase`: `phrase()`, the recovered phrase, and
  `wallet_has_passphrase()`, the answer that holds.
  `seal(mhfe, &confirmed, new_password, repair_word_count, progress, on_unverified)` encrypts that
  phrase again, in a container of the old kind, at the settings of the engine it is given, which
  `check_new` judges; `keep(work, confirmed.wallet_has_passphrase())` of the result lists what to
  keep.
- `HiddenWallets::new(container, main_passphrase)` and `open(mhfe, password, progress)` give a
  session of hidden wallets: a password used already is refused before any work
  (`PASSWORD_ALREADY_USED`), compared after normalization; `was_used(password)` lets a front end
  ask for another one first.
- `RecoveredPhrase::status(length)` says what a recovered phrase is known to be (`RecoveryStatus`),
  and `passes_wallet_check_without_passphrase()` whether a 24-word phrase passes the wallet check
  without a passphrase.
- `check_word` (the optional profile MHFE-PASSWORD-CHECK-1): `check_index` computes the check word,
  `PasswordReview::of(typed)` reads a typed password, in its written form when only that fits,
  with the repairs it offers and their order (`repairs_first`), and `apply(ReviewChoice)` gives the
  chosen password; `chosen_password(typed, repeat, choice)` compares a new password with its
  repetition first. `eff::EffList` is the EFF large wordlist the password tools share.
- `new_password::PasswordRecipe` makes a password of 1 to 32 words, of five words and their check
  word, or of 1 to 64 characters (`INVALID_PASSWORD_SIZE` otherwise), from a `random::RandomSource`
  or, for words, from real dice (`INVALID_DICE_ROLLS`). `random::check_source` refuses a source
  that cannot be random (`RANDOM_FAILED`): two blocks of 32 bytes that are equal or all zero.
  `PasswordRecipe::make` probes its source with it first, and reads a password with a check word
  back, which must fit its check word (`INTERNAL_ERROR` otherwise). `uniform_below` draws without
  bias.
  `strength::Strength::of(password)` is the rough estimate, weak below 50 bits.
- `self_test::SelfTest::published().run(mhfe, progress)` encrypts the public suite 3 vector and
  recovers the public suite 4 vector at full cost and says whether each came out as published
  (`suite_3_as_published()`, `suite_4_as_published()`, `passed()`). A witness compares every
  Argon2id call, without changing its cost or its key, with the round the published vectors record
  at that place, rounds 1 to 12 being the encryption and 13 to 24 the recovery. `fault()` of the
  result is `None` when the test passed, else a `SelfTestFault` that says where the work first
  left the published path. Its `round()` gives the round, `None` for `AfterArgon2`; `id()` gives
  "argon2-input", "argon2-key" or "after-argon2"; and `Display` gives the sentence a front end
  shows as it is, such as "first wrong round 4 of 24: Argon2id returned another key for the
  published input, so the fault is in Argon2id". `first_wrong_round()` is the round of `fault()`,
  where Argon2id's input or its key first differed, and `None` when the test passed or the fault
  lies after the last call. The module is built natively and with `browser-core`; the quick
  self-checks are in `self_check`, below. The kinds of fault:
  - `Argon2Input { round }`: Argon2id was given an input, the password after NFKD or the salt,
    that the vector does not record there, so the fault lies before Argon2id: in that round's
    salt, or in the state the round started from, which the round before made, or the packing and
    the password's encoding made for the first round of an operation;
  - `Argon2Key { round }`: the recorded input gave another key, so the fault lies in Argon2id;
  - `AfterArgon2`: every input and key was as published, so the fault lies after the last
    Argon2id call of an operation, in its last mask and state update or in writing the result.
- `memory::LockedText` and `memory::LockedBytes` hold a secret text and secret bytes in memory
  that is locked (`mlock`) before anything is written into it and unlocked only after it is wiped,
  natively on Unix; Windows and the browser lock nothing. `build(capacity, fill)` reserves the
  buffer at its final size, locks it and lets `fill` write into it, so that a `fill` that fails
  leaves its bytes wiped while still locked; `copy_of` copies into such a buffer, `is_locked()`
  says whether the system locked it, and `LockedBytes::into_text` turns bytes into text in the same
  buffer under the same lock. `memory::LockedPages` is the lock under one buffer, for a holder of
  its own.
- `phrase_from_entropy(entropy)` gives the English phrase of 16 to 32 bytes of entropy that a
  program drew itself, written into a buffer reserved at its final size and wiped when dropped.
- `check_phrase`, `read_phrase` and `check_container` validate input before any work, so a program
  can ask again at once. `read_phrase` and `check_container` return the input as it was read, every
  word in full and in lower case, for showing back to the user.
- `wallet` has the address and fingerprint functions the check uses: `Coin`, `Address` with its
  `AddressType`, `DerivationPath`, `SearchLimits`, `parse_fingerprint`, `master_fingerprint` and
  `find_address(phrase, passphrase, address, path, limits)`, which returns the path where the
  address was found. Both read the phrase with the library's one reader of phrases, as every other
  phrase input does: any spacing and letter case and the first four letters of a word, and nothing
  else (`INVALID_PHRASE`). An `Address` comes only from `Address::parse(coin, text)`;
  `SearchLimits::new` refuses counts outside 1 to 2^31, the BIP32 range of account numbers and
  address indexes. `AddressSearch::new(address, path, limits)` states what a check of the address
  will search before it runs: `type_description()`, the path `pattern()` such as
  "m/84'/0'/0'-9'/0-1/0-99", the number of `addresses()` and whether `only_path()` is searched.
  `AddressSearch::describe(coin, address, path)` does so from texts with the default limits, an
  empty `path` meaning the standard paths, and refuses an unknown coin (`INVALID_COIN`), an address
  that is not the coin's (`INVALID_ADDRESS`) and an invalid path (`INVALID_DERIVATION_PATH`); the
  browser package's `describeAddress` calls it. The module's documentation has a compiled example.
- `vectors` writes test vectors from the fixed public inputs: `PUBLIC_INPUTS` and `NEGATIVE_INPUTS`
  for suite 3, `SAME_LENGTH_INPUTS` and `SAME_LENGTH_NEGATIVE_INPUTS` for suite 4. Vectors contain
  the password and every round key by design.

Every buffer and binding this crate owns that holds a password, phrase, passphrase, state, key,
private scalar or mask is wiped when dropped. Short-lived working buffers inside dependencies, such
as those of Unicode normalization, BIP39 word parsing and elliptic-curve arithmetic, copies that
the compiler makes in registers or on the stack, and immutable JavaScript strings in the browser
are outside its control.

### Self-checks

`self_check` compares every part of the library with its known answers, so that a broken build, a
faulty processor or memory, or a damaged table that changes one of those answers shows before
anything secret is asked. Each part
brings its own check in a `known_answers` module next to its code, built only where that part is
built. A check compares exact output with a published test vector, or with a value from an
independent implementation that first reproduced a published vector, a comment beside each value
saying where it comes from; and it gives every verifier a case it must refuse, such as a card of
another plate, six words that do not fit their check word or a damaged address. A round trip
through the same code alone is never the whole check.

```rust
use mhfe::self_check::{sets, Tier};

let mut checks = sets::native(None);            // every part the command-line tool computes
let report = checks.run_quietly(Tier::Startup); // tens of milliseconds, no live randomness
report.require_passed()?;                       // MhfeError::SelfCheckFailed for the first failure
```

- `Tier::Startup` is the check of every start: milliseconds per part, without Argon2 at full size,
  live randomness, files or network. `Tier::Full` adds the slower cases, for a self-test that a
  person asks for. `Tier::name()` and `Tier::from_name()` use "startup" and "full"; another name is
  `INVALID_REQUEST`. MHFE's own published vectors at full cost take minutes and gigabytes and stay
  in `self_test`.
- `ComponentCheck` is the check of one part: `id()`, a stable identifier such as "repair-words";
  `label()`, the name a person reads, which names no coin; `runs_at(tier)`, true unless the check
  belongs to the full self-test only; and `run(tier)`, which gives a `ComponentOutcome`: `Passed`,
  `Warning(detail)` when the part works but a protection around it is weaker than it should be,
  `NotAvailable(reason)` when it cannot be checked here, `NotRun(reason)` or `Failed(detail)`.
  Only `Failed` is a failure (`is_failure()`). `name()` gives "passed", "warning", "notAvailable",
  "notRun" or "failed", and `detail()` the text, which names the case that differed by its place,
  such as "vector 4 of 10 gives another container", and never holds a secret, a coin's name, an
  address, a vector's text or an error's message. Error codes appear in a detail only as codes.
- `SelfCheck` is a set of checks, each part once: `SelfCheck::new().with(check)` adds a check unless
  one with its identifier is there already, `merge(other)` adds those of another set in the same
  way, `skip(ids)` leaves parts out, such as those another module of the same page has passed, and
  `ids()`, `contains(id)`, `len()` and `is_empty()` describe it. `run(tier, on_start, on_result)`
  runs the checks of `tier` in order, calling `on_start(id, label)` before each and
  `on_result(&ComponentResult)` after it; a check of the other tier is left out of the report.
  `run_quietly(tier)` reports nothing along the way. A front end adds checks of its own through the
  trait, as the command-line tool adds those of its process. The module measures no time.
- `SelfCheckReport` gives `tier()`, `results()` in the order the checks ran (a `ComponentResult`
  has `id()`, `label()` and `outcome()`), `passed()`, which warnings and parts not available or
  not run do not spoil, `first_failure()`, `warnings()` and `require_passed()`, which gives
  `MhfeError::SelfCheckFailed { component, detail }` with the label and the detail of the first
  part that failed.
- `self_check::sets` holds the set of each front end, each built only with the parts it checks:
  `hashes()` the cipher's hashes alone; `core(argon2)` everything encryption, recovery, the
  rehearsal check, rekey and hidden wallets compute, with the Argon2 check the caller gives (`None`
  lists `argon2` as not run, "this check leaves Argon2 out"); `repair()`; `passwords(random)`;
  `wallet(random)`, which holds `address-search` too; and, natively, `native(random)`, the core
  with `NativeArgon2Check` followed by `argon2-sizes`, `password-generator`, `random-source`,
  `address-search` and `memory-locking`, 23 parts. `random` is the generator the full self-test
  tries, `None` at start.
  `sets::NotChecked::new(id, label, reason)` lists a part as not run.

The parts, by identifier and label, and what each compares:

- `cipher-hashes`, "Cipher hashes": SHA-256 (FIPS 180-4, two messages), HMAC-SHA-256 (RFC 4231
  test cases 2 and 6) and BLAKE2b-256, as the rounds use them.
- `argon2`, "Argon2id": natively the RFC 9106 vector, which sets a secret and associated data,
  and a call shaped as MHFE makes it at 1 MiB, on each copy of the core the processor runs (SSE2,
  and SSSE3 where present), with the work area wiped after every call; in a browser the 1 MiB call
  through the page's Argon2 build. The 1 MiB tag comes from OpenSSL. Every call goes through the
  written-key guard that the engine puts around each round, natively as in a browser, so a call
  that returns without writing its key, or writes zeros, is refused. Such a call, or one that
  returns an error, gives "Argon2id could not run: …", told apart from a wrong tag ("… gives another
  tag …"). Natively that fails the part, so a command stops at start; in a browser an Argon2
  build that does not start makes the part not available instead (see
  [Browser package](#browser-package)).
- `argon2-sizes`, "Argon2id at 64 and 256 MiB", full self-test only: 64 MiB with 3 passes and
  256 MiB with 2 passes on each copy of the core, and once on one thread. A computer that cannot
  give the memory makes it not available rather than failed.
- `cipher-rounds`, "Cipher rounds": 10 of the published vectors of suites 3 and 4 replayed with
  their recorded round keys through `Encryption::run`, with its check and repair words,
  `Mhfe::decrypt`, also at each stated length, and `Mhfe::decrypt_as` with the suite selected; a
  length whose check does not match (`VERIFIER_MISMATCH`), a new container checked against other
  words (`VERIFICATION_FAILED`) and settings no vector has; and suite 4's entropy separation. The
  full self-test replays all 27 vectors.
- `formats`, "Formats": the suite 3 validation fixture, with its settings, length detection,
  verifier byte order and the refusals of phrases and containers before any Argon2 work. The full
  self-test adds the 63 refusals of suite 4.
- `container-facts`, "Container facts": what `ContainerFacts` and `OriginalFacts` say of published
  containers and phrases, and the refusal of a container of 13 words or with a wrong checksum.
- `keep-advice`, "Keep advice": the exact `keep` lists of sealed published vectors with a
  passphrase, repair words, other settings and a length that detection would not find alone.
- `password-unicode`, "Passwords (Unicode 17)": Unicode 17.0.0, the NFKD bytes of the published
  vector unicode-password and every password case of the validation fixture. The full self-test
  scans every Unicode scalar value against the refusal of control characters and separators:
  exactly 67 are refused, the 65 of General_Category Cc with U+2028 and U+2029, and NFKD makes
  none of them from another character. Whether a code point is assigned is checked only at the
  fixture's cases, which refuse the unassigned U+0378 and U+50000 and the noncharacter U+FFFE
  (`UNASSIGNED_CHARACTER`); the table of assigned characters is not scanned.
- `bip39-words`, "BIP39 words": the English list's SHA-256, 4 of the 24 Trezor vectors both ways,
  a wrong checksum refused and the completion of four-letter prefixes. Full: all 24.
- `repair-words`, "Repair words (MHFE-REPAIR-1)": the published cards of 2 to 8 words of one plate,
  the repair of two unreadable words, and too much damage and a card of another plate refused
  (`REPAIR_NOT_POSSIBLE`). Full: the cards of all four published plates and more repairs, of wrong
  words too and at the code's bound.
- `password-check-word`, "Password check word (MHFE-PASSWORD-CHECK-1)": the EFF list's SHA-256 and
  shape, the four published vectors, a forgotten word restored and six words that do not fit.
- `wallet-hashes`, "Wallet hashes": SHA-512, HMAC-SHA-512, RIPEMD-160, SHA-256 and Keccak-256.
- `bip39-seed`, "BIP39 seeds": seeds with the passphrase "TREZOR" and with one that NFKD changes,
  and a master key fingerprint with a passphrase. Full: the 24 Trezor seeds.
- `bip32`, "BIP32 keys": BIP32 test vectors 1 and 3, and a malformed fingerprint refused.
- `addresses`, "Address encodings": the master key fingerprint of the public test phrase, one
  receiving address of each encoding at its path, 18 in all, and a damaged address of each checksum
  family refused (`INVALID_ADDRESS`). Full: 43 addresses and two searches with `find_address`.
- `address-search`, "Address search", built natively and with `browser-wallet`: what
  `AddressSearch::describe` states an address check will search, its type, path pattern, number of
  addresses and whether only the given path is searched, compared whole in five cases, each with an
  address of the `addresses` part's table: BIP-0084's first receiving address on the standard paths
  (2,000 addresses) and at its one path, a test network address, an address of a coin searched under
  two coin types (4,000) and a DIP17 address. An unhardened index of 2^31
  (`INVALID_DERIVATION_PATH`), an address of another coin (`INVALID_ADDRESS`) and an unknown coin
  (`INVALID_COIN`) are refused. It derives no key, so both tiers run the same cases.
- `wallet-check`, "Wallet check (MHFE-WALLET-CHECK-SEED-1)": the whole digest and the verdict of a
  passing and a failing published vector, a draw from a scripted source, read back, and a source
  of zeros and a check without a passphrase refused. Full: every published vector.
- `hidden-wallets`, "Hidden wallets": a session on the published container zero-24, a password
  used twice and a reading that passes a built-in check refused.
- `rekey`, "Rekey": a published container sealed again under another password and other settings
  must give the published containers; the same password and settings, and a fingerprint that does
  not match, are refused.
- `rehearsal`, "Rehearsal": `Mhfe::check` of a published container with a fingerprint, an address
  at its path and the built-in check, and a fingerprint one bit off that must not match.
- `password-generator`, "Password generator": scripted bytes through the unbiased draw, the
  characters, words and check word of new passwords, and a stuck source refused. Full: the
  strength estimate.
- `random-source`, "Random source": at start scripted sources only, with no system call, so that
  the source check is known to refuse a stuck source and the spread test a narrow one. Full: the
  live source through `check_source` and `check_spread`; not run without one.
- `memory-locking`, "Locked memory": passed when memory locks, a warning when the system refuses,
  not available in WebAssembly and outside Unix.

The Argon2 checks are closed: their inputs are private constants, they take no cost and no password
and give only an outcome, so they cannot encrypt anything, and no release build holds an engine
that computes Argon2 below MHFE's cost (`scripts/check-release-artifacts.sh` looks for the marker
of the test-only engine). `engine::NativeArgon2Check::new()` starts four threads per call and joins
them before it returns. A process can enter its own network namespace only while it has a single
thread, so a command started directly runs its checks at start after it has entered its own
namespace, where the system allows one. The start menu runs them once before it opens, in its own
thread and with no network namespace: the menu enters none, and its commands, which run in threads
of it, cannot. `engine::NativeArgon2SizesCheck::new()` takes about 1.5 s and 256 MiB. Both native
checks call Argon2 through the engine's written-key guard. In a browser,
`engine::BrowserArgon2Check::new(&argon2)` also offers `verify()`, which gives `SelfCheckFailed`,
and `engine::BrowserArgon2SizesCheck::new(&argon2)` checks one build at a time.
`engine::browser::BrowserEngine::verify_known_answer()` is the check the bindings run before every
operation's first round and after its last.

`cipher-rounds` and the checks of keep advice, hidden wallets, rekey and rehearsal replay the
published vectors with `PublishedRoundKeys`, a private engine that answers only the password and
salt pairs a published vector records, with the key it records, and refuses any other call with
`INTERNAL_ERROR`. It cannot encrypt anything but a published vector, so a release build may hold
it. Its table, `src/mhfe/published_rounds.rs`, is written by `scripts/generate-published-rounds.py`
from `tests/fixtures/` (`--check` compares without writing), and a unit test compares every value
with the fixtures.

`random::RandomSourceCheck::new(live)` is the `random-source` check. `random::check_spread(source)`
refuses 1,024 bytes with fewer than 200 different values or one value more than 40 times
(`RANDOM_FAILED`); a working source fails it less than once in 2^70. No test can see a source that
is deterministic but looks random. `memory::LockProbe` is the `memory-locking` check, and
`eff::EffList::try_get()` reads the vendored EFF list or gives `INTERNAL_ERROR` for a damaged
file, which the check word's check reports at start.

### Errors

`MhfeError` has a readable message (`Display`) that never contains a secret, and a stable code
(`code()`):

| Code                              | Meaning                                                                             |
| --------------------------------- | ----------------------------------------------------------------------------------- |
| `INVALID_PHRASE`                  | The original phrase is not a valid English BIP39 phrase                             |
| `INVALID_CONTAINER`               | The container is not a valid English BIP39 phrase, or not one of the selected suite |
| `INVALID_WORD_COUNT`              | A length other than 12, 15, 18, 21 or 24 was chosen                                 |
| `SAME_LENGTH_NEEDS_SHORT_PHRASE`  | A same-length container was asked for a 24-word original                            |
| `LENGTH_CHOICE_NOT_APPLICABLE`    | The chosen length does not fit the container's word count                           |
| `NO_BUILT_IN_CHECK`               | The built-in check was asked for a same-length container                            |
| `NO_WALLET_CHECK`                 | The wallet check was asked for a same-length container                              |
| `REFERENCE_REQUIRED`              | A recovery to encrypt again has no built-in check and no address or fingerprint     |
| `REFERENCE_MISMATCH`              | The phrase recovered to encrypt again does not match the address or fingerprint     |
| `HIDDEN_WALLET_PASSES_CHECK`      | A hidden wallet's phrase passes the built-in check of a shorter phrase              |
| `INVALID_REPAIR_WORDS`            | Repair words that are not 2, 4, 6 or 8 English BIP39 words                          |
| `REPAIR_NOT_POSSIBLE`             | No repair within the repair words' bound passes the BIP39 checksum                  |
| `INVALID_PIM`                     | PIM outside 0 to 1023                                                               |
| `INVALID_MEMORY_LEVEL`            | Memory level outside 0 to 21                                                        |
| `EMPTY_PASSWORD`                  | The password is empty                                                               |
| `PASSWORD_TOO_LONG`               | More than 1024 bytes after normalization                                            |
| `INVALID_PASSWORD_UTF8`           | The password bytes are not UTF-8                                                    |
| `CONTROL_CHARACTER_IN_PASSWORD`   | The password has a control character, U+2028 or U+2029                              |
| `UNASSIGNED_CHARACTER`            | The password has a code point unassigned in Unicode 17.0.0                          |
| `VERIFIER_MISMATCH`               | A chosen short length does not pass its check                                       |
| `FIXED_POINT`                     | The container would equal the original                                              |
| `VERIFICATION_FAILED`             | The new container did not decrypt to the original; discarded                        |
| `CANCELLED`                       | The progress callback stopped the operation                                         |
| `INVALID_ADDRESS`                 | The check's address cannot be used                                                  |
| `INVALID_DERIVATION_PATH`         | The check's path is malformed                                                       |
| `INVALID_FINGERPRINT`             | The fingerprint is not eight hexadecimal digits                                     |
| `NOT_ENOUGH_MEMORY`               | Less free memory than the level needs, also within a cgroup                         |
| `MEMORY_ALLOCATION_FAILED`        | The operating system refused the memory                                             |
| `MEMORY_LEVEL_NOT_SUPPORTED_HERE` | The build cannot address that much memory (browser: > 0)                            |
| `ARGON2_FAILED`                   | The Argon2 code reported an error                                                   |
| `INVALID_PASSPHRASE`              | The BIP39 passphrase bytes are not UTF-8                                            |
| `INVALID_REQUEST`                 | A choice the API does not know, or a step out of its order                          |
| `INVALID_COIN`                    | An address's coin is not one the check knows                                        |
| `INVALID_PASSWORD_SIZE`           | A generated password of more words or characters than allowed, or none              |
| `INVALID_DICE_ROLLS`              | Dice digits for a word are not five digits from 1 to 6                              |
| `PASSWORD_REPAIR_NOT_OFFERED`     | A check word choice the review did not offer                                        |
| `PASSWORDS_DIFFER`                | A new password and its repetition differ                                            |
| `WALLET_CHECK_NEEDS_PASSPHRASE`   | The wallet check was asked for without a BIP39 passphrase                           |
| `RANDOM_FAILED`                   | The random source failed or gave bytes that cannot be random                        |
| `PASSWORD_ALREADY_USED`           | A hidden wallet's password was used already in this session                         |
| `OTHER_WALLETS_NOT_CONFIRMED`     | A rekey without the owner's yes that other passwords' wallets are safe              |
| `NEW_PASSWORD_SAME_AS_OLD`        | A rekey that would give the old container again                                     |
| `NOT_CONFIRMED_BY_OWNER`          | The owner said the recovered phrase is not theirs                                   |
| `SELF_CHECK_FAILED`               | A part gave another answer than its known one: do not use the program here          |
| `INTERNAL_ERROR`                  | Anything else                                                                       |

## Browser package

`scripts/build-wasm.sh` writes the package to `dist/`: the runtime every class shares, with one
WebAssembly (`runtime/mhfe.wasm`) and one worker script (`runtime/worker.js`), and a folder per
module class; [`BROWSER-PACKAGE.md`](BROWSER-PACKAGE.md) explains how to embed it and what a page
must do. The WebAssembly is this crate with the Cargo feature `wasm`, which turns on every module's
bindings (`browser-core`, `browser-repair`, `browser-passwords`, `browser-wallet`); each feature
also builds alone, for a program that needs only some modules. Every class takes the same
`workerSource` and `wasm`, the bytes of `runtime/mhfe.wasm` or the module compiled from them;
`MhfeClient` also takes the text of the two Argon2 builds:

```js
// core/client.js (typed in core/client.d.ts)
const client = new MhfeClient({ workerSource, wasm, argon2Threaded, argon2SingleThreaded });
client.mode(); // "fast" on a cross-origin isolated page, otherwise "standard"
client.maxSupportedMemLevel(); // 0: what the build supports; free memory is not measured
await client.startupCheck({ argon2 }); // { passed, tier, version, buildId, components }
// argon2: true (the default) or false; every other method but parameters() and selfTest()
// awaits a startup check before its first call, startupCheck({ argon2: false }) if none ran
await client.fullCheck({ onProgress }); // the same report at the full tier, run anew each time
await client.parameters(); // { version, suiteId, ..., repairCapacities }
await client.readPhrase(phrase); // { phrase, words, otherLengths, containers }
await client.readContainer(container);
// { container, words, suiteId, phraseLengths, builtInCheckLengths, confirmationFor, ... }
await client.encrypt({
  phrase,
  password,
  passwordRepeat,
  passwordRepair, // "asTyped" (the default), "corrected" or { repair: position }
  pim, // 0 (the default) to 1023
  memoryLevel, // 0, the default and the only level a browser supports
  sameLength, // default false
  repairWordCount, // 0 (the default), 2, 4, 6 or 8
  walletHasPassphrase, // required, true or false: does the wallet have a BIP39 passphrase?
  onProgress,
  onUnverified,
}); // a sealed container, once its check has passed
await client.decrypt({ container, password, passwordRepair, pim, memoryLevel, words, onProgress });
// words: 0 (the default) detects the length; or 12, 15, 18, 21 or 24
await client.check({
  container,
  password,
  passwordRepair,
  pim,
  memoryLevel,
  reference,
  passphrase,
  onProgress,
});
// reference: exactly one of { address, coin, path? }, { fingerprint }, { words } or
// { walletCheck: true }; coin and path only with an address. { walletCheck: true } compares the
// 24-word reading only and needs a 24-word container (NO_WALLET_CHECK) and then a passphrase
// (WALLET_CHECK_NEEDS_PASSPHRASE), both checked before the first round.
await client.rekey({
  container,
  words, // the phrase's word count; required for a 24-word container
  password,
  passwordRepair,
  pim,
  memoryLevel,
  otherWalletsMoved: true,
  newPassword,
  newPasswordRepeat,
  newPasswordRepair,
  newPim,
  newMemoryLevel,
  repairWordCount,
  confirmation, // { builtInCheck: true }, { address, coin, path? }, { fingerprint } or { owner }
  passphrase, // the wallet's BIP39 passphrase, only with an address or a fingerprint
  walletHasPassphrase, // required unless passphrase is not empty
  onProgress,
  onUnverified,
}); // a sealed container, as from encrypt
// keep lists { item: "containerWords", words }, { item: "password" }, then where needed
// { item: "passphrase" }, { item: "repairWords" }, { item: "pim", value },
// { item: "memoryLevel", value } and { item: "wordCount", words }, in this order.
const session = await client.openHiddenWallets({ container, pim, memoryLevel, mainPassphrase });
await session.open({ password, passwordRepeat, passwordRepair, onProgress });
// { phrase, words, fingerprintWithoutPassphrase }
await session.close(); // the session's passwords are overwritten; during an open its worker stops
await client.selfTest({ onProgress }); // { passed, suite3, suite4, firstWrongRound, fault }
client.cancel(); // rejects the running operation or session with MhfeCancelledError

// repair/repair.js
const repair = new MhfeRepair({ workerSource, wasm });
await repair.startupCheck(); // awaited by every method but parameters() before its first call
await repair.fullCheck({ onProgress });
await repair.parameters(); // { version, profile, repairWordCounts, ..., repairCapacities }
await repair.repairWords({ container, count }); // { profile, words, repairsUnreadable, ... }
await repair.repairPlate({ plate, card }); // { container, containerFingerprint, unchanged, ... }

// passwords/passwords.js
const passwords = new MhfePasswords({ workerSource, wasm });
await passwords.startupCheck(); // awaited by every method but parameters() before its first call
await passwords.fullCheck({ onProgress });
await passwords.parameters(); // { version, checkWordProfile, defaultWords, ..., weakBelowBits }
await passwords.review({ password, passwordRepeat }); // { profile, reading, ..., repairs }
// Without passwordRepeat the password was typed once; with it, an empty one included, the two
// must be the same (PASSWORDS_DIFFER).
await passwords.strength({ password, passwordRepair }); // { bits, weak }
await passwords.make({ kind, count, dice }); // { password, bits, weak, checkWord }
// make() gives five words. kind "words" (the default) takes count 1 to 32, default 5;
// "characters" 1 to 64, default 16; "checkWord" gives five words and their check word and takes
// no count: a count other than undefined is a TypeError, before any worker starts.

// wallet/wallet.js
const wallet = new MhfeWallet({ workerSource, wasm });
await wallet.startupCheck(); // awaited by every method but parameters() and cancel()
await wallet.fullCheck({ onProgress });
await wallet.parameters(); // { version, coins, walletCheckBits, drawReportInterval }
await wallet.walletCheck({ phrase, passphrase }); // a boolean; 24 words and a passphrase only
await wallet.fingerprint({ phrase, passphrase }); // eight hex digits; passphrase may be ""
// "73c5da0a" for the public test phrase, "abandon" eleven times and "about", without one; the
// phrase is read as everywhere, in any letter case and spacing, four letters of a word enough
await wallet.describeAddress({ address, coin, path }); // { type, search, addresses, onlyPath }
await wallet.drawPhrase({ passphrase, passphraseRepeat, walletCheck, workers, onProgress });
// { phrase, words, walletCheck, fingerprintWithPassphrase, workers }
wallet.cancel(); // rejects the phrase being drawn with MhfeCancelledError
```

`walletHasPassphrase` is the user's answer whether the wallet has a BIP39 passphrase. MHFE encrypts
only the phrase, so with `true` the result's `keep` names the passphrase. `encrypt` requires it: a
missing value, or one that is not `true` or `false`, rejects with a `TypeError`. In `rekey` a value
other than `true`, `false` or `undefined`, `null` included, is a `TypeError` too, and so is a
`passphrase` that is not empty with `{ builtInCheck: true }` or `{ owner }`: a passphrase belongs
only to an address or a fingerprint. The library then judges the answer with the confirmation. Only
an address or a fingerprint compared with a `passphrase` that is not empty shows that the wallet
has one: there the answer may be left out, and `false` is refused with `INVALID_REQUEST`.
Everywhere else the answer is required (`INVALID_REQUEST` without it): `{ builtInCheck: true }` and
`{ owner }` show nothing of a passphrase, and an address or a fingerprint with an empty
`passphrase` matches the phrase's wallet without one, which proves nothing about funds under a
passphrase; there `true` is taken and `keep` names the passphrase. For a length without a built-in
check, `{ builtInCheck: true }` is refused with `REFERENCE_REQUIRED` before the answer is judged.
All these refusals come before the first round; in a browser the worker has then run only the
small known answer of its Argon2 build. `core/client.d.ts` types an address or a
fingerprint confirmation in two forms: with a `passphrase` and an optional `walletHasPassphrase`,
or without a `passphrase` and with `walletHasPassphrase` required. A type cannot tell an empty
`passphrase`, so an empty one fits the first form and is refused without the answer when the rekey
runs.

`startupCheck()` and `fullCheck()` run the self-checks of a class (see
[Self-checks](#self-checks)) and resolve to a report,
`{ passed, tier, version, buildId, components: [{ id, label, outcome, detail? }] }`: `outcome` is
"passed", "warning", "notAvailable", "notRun" or "failed", and `passed` is false only when a part
failed. The page's own parts come first. `browser-features`, "Browser features", needs
WebAssembly, workers, Blob URLs and `TextEncoder`, `crypto.getRandomValues` for the password and
wallet classes, shared memory for the threaded Argon2 build on a cross-origin isolated page, and a
WebAssembly that compiles under the page's Content-Security-Policy. `package-parts`, "Package
parts", needs the class and the runtime of one build. The classes that take secrets add
`page-encoding`, "Text encoding of the page": the UTF-8 bytes of the password of the published
vector unicode-password, and the refusal of a lone surrogate. The class's own parts follow: those of
`sets::core`, `sets::repair`, `sets::passwords` or `sets::wallet`, at start without live randomness
and in the full check with the worker's `crypto.getRandomValues`. A startup report is made once
for each class and choice; a part that another class has passed with the same WebAssembly
object is not run again and is listed as that class found it. `fullCheck()` runs every part anew.
`MhfeClient.fullCheck()` adds Argon2 at 64 and 256 MiB with each Argon2 build in turn,
`argon2-sizes-single-threaded` and `argon2-sizes-threaded` (not run on a page that is not
cross-origin isolated), and lists `published-vectors` as not run, since `selfTest()` runs them, and
`memory-locking`, `core-dumps`, `isolation` and `hidden-input` as not available, each with the
reason. `onProgress` receives `{ id, label, running: true }` as a part starts and its result with
`running: false` as it ends.

An Argon2 build that does not start, as when the browser refuses its memory or its lane workers,
gave no wrong answer. When no build in front of the worker starts, `MhfeClient`'s Argon2 parts are
"notAvailable", with the detail "Argon2id could not run: the threaded Argon2 build did not start:
…", where … is the cause (or "single-threaded"; both causes, joined by "; ", when both builds were
tried). In fast mode the core's check places the single-threaded build in front of the worker too,
after the threaded one: when only the threaded build does not start, the check runs the
single-threaded one instead, and a passing `argon2` part becomes a "warning" with "the threaded
Argon2 build did not start: …; the check ran the single-threaded build of the standard mode
instead". A wrong answer of that build still fails, the same note before its detail. Operations are
unchanged: they use their mode's build and, when it does not start, reject with their own error.

A failed part closes the class for good: every call that awaits the check, and every later one,
rejects with `SELF_CHECK_FAILED`, whose message names the part and the case and whose `report` is
the report. A failed `fullCheck()` closes the class too. `WORKER_FAILED` and `PACKAGE_MISMATCH`
give no report and close nothing: the next call checks again. A startup report with a part that is
"notAvailable" or a "warning", which at start only an Argon2 build that did not start gives, passes
but is not kept either: the next call checks again. Secrets are copied into bytes only after the
check has passed. Every operation that runs Argon2, `selfTest()` included, also computes
Argon2's 1 MiB known answer through its build before its first round and after its last, and a
session of hidden wallets when it starts: a different answer rejects with `SELF_CHECK_FAILED`, in
place of the operation's own error if it had one, and its result is dropped.

Every method returns a promise and reports every error by rejecting it, the checks of its arguments
included; none throws when it is called. Only the constructors throw, a `TypeError` for a missing
or wrong package part. `mode()`, `maxSupportedMemLevel()` and the `cancel()` of `MhfeClient` and
`MhfeWallet` are synchronous. A wrongly typed argument rejects with a `TypeError`, except a number
of the core's settings and lengths, which rejects with its own code (`INVALID_PIM`,
`INVALID_MEMORY_LEVEL`, `INVALID_WORD_COUNT`, `INVALID_REPAIR_WORDS`). Every other error
is an `MhfeError` whose `message` is an English sentence a page can show as it is. Its `code` is
one of the codes above or one of the browser's own:

- `INVALID_PASSWORD_TEXT`: a string with an unpaired surrogate;
- `PASSPHRASES_DIFFER`: a new phrase's passphrase and its repetition differ;
- `BUSY`: another long operation or session runs, a wallet of the session is being opened, or a
  phrase is being drawn;
- `SESSION_CLOSED`: a session of hidden wallets was used after it ended;
- `WORKER_FAILED`: the WebAssembly did not compile, the browser refused or lost the worker, or the
  worker did not start within a minute;
- `PACKAGE_MISMATCH`: files of different builds of the package, an Argon2 build among them, or a
  `core/client.js` whose limits differ from the WebAssembly's; take every file from one build;
- `CALLBACK_FAILED`: a callback of the page threw, or was async and its promise rejected while the
  operation ran, so the operation was stopped and its worker ended; the page's error is the
  `cause`.

`MhfeErrorCode` in `runtime/runtime.d.ts` lists every code. `onProgress` receives
`{ stage, round, rounds }`, and that of `drawPhrase` `{ stage: "draw", draws }`; the stages are
listed in BROWSER-PACKAGE.md.

The WebAssembly's exports are in `src/wasm_api/`, a file per module: the core's `suiteParameters`,
`checkPassword`, `describePhrase`, `describeContainer`, `encrypt`, `decrypt`, `check`, `selfTest`
and the classes `RekeySession` and `HiddenWalletSession`; the repair module's `repairParameters`,
`repairWords` and `repairPlate`; the passwords module's `passwordParameters`, `reviewPassword`,
`passwordStrength` and `makePassword`; the wallet module's `walletParameters`, `walletCheck`,
`walletFingerprint`, `describeAddress` and `drawPhrase`; and `packageVersion`. Each module has
its self-check: the core's `selfCheckCore(tier, skipIds, argon2, onStart, onResult)`, `argon2`
optional, and `selfCheckArgon2(tier, skipIds, argon2, onStart, onResult)`, which checks one
Argon2 build alone, at 1 MiB and in the full tier at 64 and 256 MiB;
`selfCheckRepair(tier, skipIds, onStart, onResult)`;
`selfCheckPasswords(tier, skipIds, random, onStart, onResult)`; and
`selfCheckWallet(tier, skipIds, random, onStart, onResult)`. Each runs its set at `tier`,
"startup" or "full" (`INVALID_REQUEST` otherwise, before any part runs), without the parts in
`skipIds`, calls `onStart(id, label)` before each part and `onResult(json)` after it, and returns
JSON `{ version, tier, passed, ids, components }`, `ids` naming every part of the set in its order,
the skipped ones included. `selfCheckWallet`'s set holds `address-search`, which checks what
`describeAddress` states, since both call `AddressSearch::describe`. `selfTest` returns
`{ passed, suite3: { vector, asPublished }, suite4: { vector, asPublished }, firstWrongRound,
fault }`: `fault` is null when the test passed, else `{ kind, round, message }` from the library's
`SelfTestFault`, its `id()`, its `round()` (null for "after-argon2") and its sentence, and
`firstWrongRound` is that round.
The bindings take the answer about the wallet's BIP39 passphrase strictly: `encrypt` only as a
boolean, and `RekeySession.recover` as a boolean or, when no answer is given, `undefined` or
`null`. Anything else is refused with `INVALID_REQUEST` ("walletHasPassphrase must be true or
false: whether the wallet has a BIP39 passphrase"). `RekeySession.recover` also refuses a
passphrase that is not empty with `"builtInCheck"` or `"owner"` (`INVALID_REQUEST`, "a passphrase
belongs to an address or fingerprint confirmation"); both come before the library judges the
answer as above.
Secrets are UTF-8 bytes, which the bindings wipe: passwords, BIP39 passphrases, dice rolls and the
phrase of `describePhrase`, `encrypt`, `walletCheck` and `walletFingerprint`, whose bytes are
`INVALID_PHRASE` when they are not UTF-8. wasm-bindgen would copy a text argument into the
WebAssembly's memory and free it without overwriting it. A container, a plate and repair words
arrive as text, as the library keeps them: without the password they reveal nothing of the phrase. A
result that holds a secret is written into a buffer of its final size, wiped once it has become a
JavaScript string. Numbers are taken as JavaScript numbers and refused with their error code unless
they are whole numbers in range, so that no value wraps around; `makePassword` takes `undefined` or
`null` as the default size, and with "checkWord" any other size is `INVALID_REQUEST` ("checkWord
takes no count: it always makes five words and their check word"), as `mhfe password` refuses
`--check-word` with `--words`. Randomness for new passwords and phrases comes from
`{ fill(bytes) }`, an object the worker passes in and backs with its own `crypto.getRandomValues`;
a page does not supply it.

The package identifies itself by its release version, `version` in every `parameters()` and
`packageVersion()`. Earlier builds reported a separate counter instead:
`apiVersion` 1 in v0.3.0, 6 in v0.4.0 and 7 in v0.5.0; `version` replaced it in v0.5.1. Its files
also carry their build, `BUILD_ID` of `runtime/runtime.js` and `buildId` of `modules.json` and of
every self-check report. `scripts/stamp-build-id.mjs` derives it from the nine files a page loads,
read before any is stamped: `runtime/mhfe.wasm`, `runtime/runtime.js`, `runtime/worker.js`,
`core/client.js`, `core/argon2-mt.js`, `core/argon2-st.js`, `repair/repair.js`,
`passwords/passwords.js` and `wallet/wallet.js`. The build is the first 16 hex digits of the SHA-256
of a list with one line per file in that order, its SHA-256, two spaces and its path, as
`sha256sum` prints it, so two builds that differ in one script alone get different identifiers. The
script writes it into `runtime/mhfe.wasm` as the custom section `mhfe-build` and into the build
constant of each of the eight scripts; each Argon2 build ends with its own,
`ARGON2_THREADED_BUILD_ID` or `ARGON2_SINGLE_THREADED_BUILD_ID`, which `scripts/build-wasm.sh`
appends. Files of different builds are refused with `PACKAGE_MISMATCH` before they work together:
a class and the runtime, the runtime and the worker, the worker and the WebAssembly, and the worker
and an Argon2 build in front of it, which is refused before it starts, also when it carries no
build. This catches files mixed by accident, not deliberate tampering, which `SHA256SUMS` and its
signature cover.

## Compatibility

A change to any value the specification freezes (suite identifier, rounds, packing, password
encoding, salt or mask derivation, Argon2 parameters, the PIM or memory-level mapping) needs a new
suite identifier. The test vectors in `tests/fixtures/suite3-vectors/` and
`tests/fixtures/suite4-vectors/` and the fast fixtures `tests/fixtures/validation-cases.json` and
`tests/fixtures/suite4-vectors/validation-cases.json` catch such a change.
