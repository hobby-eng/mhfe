# MHFE implementation API

This describes the Rust library and the browser package of suite `MHFE-BIP39-256-EXPERIMENTAL-3`.
The command-line tool is described in the [README](README.md).

## Rust library

```rust
use mhfe::{Mhfe, Password, PhraseLength, Recovery, Reference, WorkFactor};

let work = WorkFactor::new(0, 0)?;            // PIM 0..=1023, memory level 0..=21
let password = Password::new("...")?;        // NFKD with Unicode 17.0.0, 1 to 1024 bytes
let mut mhfe = Mhfe::new(work)?;              // checks free memory, reserves the Argon2 work area

let container = mhfe.encrypt(original, &password, &mut |round, rounds| {
    println!("Round {round}/{rounds}");       // return Err(MhfeError::Cancelled) to stop
    Ok(())
})?;

match mhfe.decrypt(&container, &password, PhraseLength::Detect, &mut |_, _| Ok(()))? {
    Recovery::Phrase(phrase) => { /* phrase.words, phrase.verified, phrase.phrase */ }
    Recovery::Ambiguous(candidates) => { /* show every candidate; the last one is 24 words */ }
}

let matches: bool = mhfe.check(&container, &password, &reference, &mut |_, _| Ok(()))?;
```

- `WorkFactor` holds the two settings and computes the Argon2 cost with integers only:
  `memory_kib()`, `passes()`, `estimated_seconds()`.
- `Mhfe::new` refuses a memory level the build cannot address
  (`MhfeError::MemoryLevelNotSupportedHere`: a native build is always 64-bit and supports every
  level, the browser build level 0 only, see `engine::HIGHEST_MEMORY_LEVEL`) or the computer cannot
  provide (`MhfeError::NotEnoughMemory`), and reserves the work area once; every round of every
  operation reuses it. The engine is the vendored reference C code (`engine::NativeEngine`).
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
- `encrypt` is `encrypt_unchecked` (rounds 1 to 12, returns a `NewContainer`) followed by
  `check_new_container` (rounds 13 to 24). A program that shows the container to a person between
  the two must mark it as not yet verified and report the outcome of the check, as the specification
  requires; a result for another program should come from `encrypt`.
- The progress callback receives the round that starts and the number of rounds: 1 to 24 for
  `encrypt`, 1 to 12 for `decrypt` and `check`. An error it returns stops the operation before the
  next round.
- `decrypt` with `PhraseLength::Detect` tests the 12-, 15-, 18- and 21-word layouts. One match gives
  a verified phrase; no match gives the 24-word reading, not verified; several matches give
  `Recovery::Ambiguous` with every matching candidate and the unverified 24-word reading.
  `PhraseLength::Words(n)` selects the length: a short length must pass its check
  (`MhfeError::VerifierMismatch` otherwise), 24 words are always accepted.
- `check` compares the recovery with a `Reference`: `BuiltInCheck { words }` for a 12- to 21-word
  original, `Address { address, passphrase, path, limits }` for a receiving address (the strong
  check) or `Fingerprint { fingerprint, passphrase }` for the BIP32 master key fingerprint. It
  returns only whether the recovery matches.
- `check_phrase`, `read_phrase` and `check_container` validate input before any work, so a program
  can ask again at once. `read_phrase` and `check_container` return the input as it was read, every
  word in full and in lower case, for showing back to the user.
- `wallet` has the address and fingerprint functions the check uses: `BitcoinAddress`,
  `DerivationPath`, `SearchLimits`, `master_fingerprint`, `find_address`, `address_at`.
- `vectors` writes test vectors from the fixed public inputs `PUBLIC_INPUTS` and `NEGATIVE_INPUTS`.
  Vectors contain the password and every round key by design.

Every buffer this crate owns that holds a password, phrase, passphrase, state, key or mask is wiped
when dropped. Short-lived working buffers inside dependencies, such as those of Unicode
normalization and BIP39 word parsing, are outside its control, and so are immutable JavaScript
strings in the browser.

### Errors

`MhfeError` has a readable message (`Display`) that never contains a secret, and a stable code
(`code()`):

| Code                              | Meaning                                                      |
| --------------------------------- | ------------------------------------------------------------ |
| `INVALID_PHRASE`                  | The original phrase is not a valid English BIP39 phrase      |
| `INVALID_CONTAINER`               | The container is not a valid 24-word English BIP39 phrase    |
| `INVALID_WORD_COUNT`              | A length other than 12, 15, 18, 21 or 24 was chosen          |
| `INVALID_PIM`                     | PIM outside 0 to 1023                                        |
| `INVALID_MEMORY_LEVEL`            | Memory level outside 0 to 21                                 |
| `EMPTY_PASSWORD`                  | The password is empty                                        |
| `PASSWORD_TOO_LONG`               | More than 1024 bytes after normalization                     |
| `INVALID_PASSWORD_UTF8`           | The password bytes are not UTF-8                             |
| `CONTROL_CHARACTER_IN_PASSWORD`   | The password has a control character, U+2028 or U+2029       |
| `UNASSIGNED_CHARACTER`            | The password has a code point unassigned in Unicode 17.0.0   |
| `VERIFIER_MISMATCH`               | A chosen short length does not pass its check                |
| `FIXED_POINT`                     | The container would equal the original                       |
| `VERIFICATION_FAILED`             | The new container did not decrypt to the original; discarded |
| `CANCELLED`                       | The progress callback stopped the operation                  |
| `INVALID_ADDRESS`                 | The check's address cannot be used                           |
| `INVALID_DERIVATION_PATH`         | The check's path is malformed                                |
| `INVALID_FINGERPRINT`             | The fingerprint is not eight hexadecimal digits              |
| `NOT_ENOUGH_MEMORY`               | Less free memory than the level needs, also within a cgroup  |
| `MEMORY_ALLOCATION_FAILED`        | The operating system refused the memory                      |
| `MEMORY_LEVEL_NOT_SUPPORTED_HERE` | The build cannot address that much memory (browser: > 0)     |
| `PROCESSOR_NOT_SUPPORTED`         | The SSSE3 build runs on a processor without SSSE3            |
| `ARGON2_FAILED`                   | The Argon2 code reported an error                            |
| `INTERNAL_ERROR`                  | Anything else                                                |

## Browser package

`scripts/build-wasm.sh` writes the package to `dist/`; [`web/README.md`](web/README.md) explains how
to embed it. The page-side API (`client.js`, typed in `client.d.ts`):

```js
const client = new MhfeClient({ workerSource, argon2Threaded, argon2SingleThreaded, coreWasm });
client.mode(); // "fast" on a cross-origin isolated page, otherwise "standard"
client.maxSupportedMemLevel(); // 0
await client.encrypt({
  phrase,
  password,
  passwordRepeat,
  pim,
  memoryLevel,
  onProgress,
  onUnverified,
});
// { container } after the check; onUnverified({ container }) comes after round 12
await client.decrypt({ container, password, pim, memoryLevel, words, onProgress });
// { kind: "phrase" | "ambiguous", candidates: [{ words, verified, phrase }] }
await client.check({ container, password, reference, passphrase, onProgress }); // { matches }
// reference: exactly one of { address, path? }, { fingerprint } or { words }
await client.readPhrase(phrase); // { phrase, words, otherLengths }: every word written out, no Argon2
// otherLengths: other lengths whose check the packed phrase also passes; almost always empty
await client.readContainer(container); // { container }
client.cancel(); // rejects the running operation with MhfeCancelledError
```

The five operations `encrypt`, `decrypt`, `check`, `readPhrase` and `readContainer` return a promise
and report every error by rejecting it, the checks of their arguments included; none throws when it
is called. `mode()`, `maxSupportedMemLevel()` and `cancel()` are synchronous, and only the
constructor throws, for missing package parts.
Errors are `MhfeError` objects whose `message` is an English sentence a page can show as it is,
with the codes above, plus `INVALID_PASSWORD_TEXT` (a password string
with an unpaired surrogate), `PASSWORDS_DIFFER` (`encrypt` got two different passwords), `BUSY`
(another operation runs), `WORKER_FAILED` and `CALLBACK_FAILED`: a callback of the page
(`onProgress`, `onUnverified`) threw, or was async and its promise rejected while the operation
ran, so the operation was stopped and its worker ended; the page's error is the `cause`. The client
does not wait for a callback's promise. A wrongly typed argument rejects with a `TypeError`. `onProgress` receives
`{ round, rounds }`, with `rounds` 24 for an encryption and 12 otherwise.

Inside the worker, the WebAssembly core exports `suiteParameters`, `checkPhrase`, `readPhrase`,
`otherDetectedLengths`, `checkContainer`, `checkPassword`, `encrypt`, `decrypt` and `check`
(`src/wasm_api.rs`). `otherDetectedLengths`, like `otherLengths` of the client, lists the other
source lengths whose check a phrase also passes; when it is not empty, automatic detection would not
give the phrase back on its own, and the user must remember and select its word count. `readPhrase`
and `checkContainer` return their input with every word written out. `encrypt`, `decrypt` and
`check` take the Argon2 bridge from `web/argon2-engine.js` and a progress callback
`(round, rounds)`; `encrypt` also takes a callback that receives the container before its check.
Passwords are UTF-8 bytes. The PIM, memory level and word count are taken as JavaScript numbers and
refused with their error code unless they are whole numbers in range, so that no value wraps around.

## Compatibility

A change to any value the specification freezes (suite identifier, rounds, packing, password
encoding, salt or mask derivation, Argon2 parameters, the PIM or memory-level mapping) needs a new
suite identifier. The test vectors in `tests/fixtures/` and the fast fixture
`tests/fixtures/validation-cases.json` catch such a change.
