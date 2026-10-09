# MHFE browser package

This package runs MHFE in a web page: it encrypts an English BIP39 seed phrase into a 24-word
container (suite 3, `MHFE-BIP39-256-EXPERIMENTAL-3`) or, on the user's choice, a 12- to 21-word
phrase into a container of the same length (suite 4, `MHFE-BIP39-LP-EXPERIMENTAL-4`), recovers the
phrase from either, rehearses a recovery without showing the phrase, and offers the other features
of the `mhfe` command-line tool: new phrases, rekey, hidden wallets, repair words, the password
check word, the password generator and strength estimate, the wallet check, master key
fingerprints and the self-test. What only a terminal or the operating
system can give is listed
[further down](#what-the-command-line-tool-has-and-the-browser-does-not). All the logic is the
same Rust code as in the command-line tool; Argon2 is the same reference C code, compiled to
WebAssembly.

It is experimental and has not been independently reviewed. Do not use it to protect real funds. A
page built on it says so too.

## Modules

The package is a set of independent module classes over one WebAssembly. A page or another program
takes only the classes it needs; each needs nothing but the shared runtime, and only the core needs
the Argon2 builds.

| Folder       | Class           | What it does                                                                             |
| ------------ | --------------- | ---------------------------------------------------------------------------------------- |
| `runtime/`   |                 | The WebAssembly, the worker, errors and the handling of secrets, shared by all           |
| `core/`      | `MhfeClient`    | Encryption, recovery, the rehearsal check, rekey, hidden wallets and the self-test       |
| `repair/`    | `MhfeRepair`    | Repair words of a container (MHFE-REPAIR-1) and the repair of a damaged container phrase |
| `passwords/` | `MhfePasswords` | The check word review of a password (MHFE-PASSWORD-CHECK-1), strength, new passwords     |
| `wallet/`    | `MhfeWallet`    | The wallet check of a phrase, master key fingerprints, address searches, new phrases     |

`runtime/` holds `runtime.js` and its type declarations, `mhfe.wasm`, the Rust library with
every module, and `worker.js`, the self-contained worker script that runs it. Each module folder
holds its class (an ES module that imports `../runtime/runtime.js`) and its type declarations. The
core also holds `argon2-mt.js`, Argon2 with four threads for cross-origin isolated pages,
`argon2-st.js`, with one thread for every other page including `file://`, and `mhfe-fast-mode.py`,
the package's launcher for the fast mode. `modules.json` gives the package version and, for the
runtime and each module, its files with their SHA-256; the end of this file lists the same.

The modules share one WebAssembly because they share most of their code, such as the word list,
the Unicode tables, hashing and BIP39: as separate files they were together more than twice its
size, and a page with several classes would have loaded that code several times. The modules stay
separate in the Rust library, each behind its own Cargo feature (`browser-core`, `browser-repair`,
`browser-passwords`, `browser-wallet`), so another program can build a WebAssembly with only the
ones it needs.

Nothing is fetched at run time. The page passes the files to each class as text and bytes, so it
works under a Content-Security-Policy such as
`default-src 'none'; script-src 'sha256-...' 'wasm-unsafe-eval'; connect-src 'none'; worker-src blob:`.
Every class takes `workerSource`, the text of `runtime/worker.js`, and `wasm`, `runtime/mhfe.wasm`
as bytes (`Uint8Array`) or as a `WebAssembly.Module`. `MhfeClient` also takes the text of the two
Argon2 builds. A class compiles bytes once; a page with several classes compiles the file once
itself, with `WebAssembly.compile`, and passes the module to each. Every operation runs in a new
worker made from a Blob of the worker script; a session of hidden wallets keeps its worker until it
ends. A constructor throws a `TypeError` when a part is missing or of the wrong type; nothing else
throws.

The package has one version, the release version: every class's `parameters()` reports it as
`version`, and the WebAssembly as `packageVersion()`. Each build of it also has an identifier,
`buildId` in `modules.json` and `BUILD_ID` in `runtime/runtime.js`, derived from every file a page
loads: the first 16 hex digits of the SHA-256 of a list of their SHA-256 sums, taken before the
build is stamped into them. Two builds that differ in one script alone therefore get different
identifiers. It is stamped into the WebAssembly, the worker, the runtime, every class and both
Argon2 builds. Files of different builds are refused with `PACKAGE_MISMATCH` before they work
together, an Argon2 build before it starts, so take every file of the package from one build.
The repository's
[`docs/API.md`](https://github.com/hobby-eng/mhfe/blob/main/docs/API.md#browser-package) lists the
files and the comparisons.

Every class checks its parts before its first operation and stays closed if one gives a wrong
answer; [Self-checks](#self-checks) says what is checked and what the page shows.

## Use

### Core

```js
import { MhfeClient } from "./core/client.js";

const wasm = await WebAssembly.compile(mhfeWasmBytes); // runtime/mhfe.wasm, once per page
const client = new MhfeClient({
  workerSource, // text of runtime/worker.js
  wasm, // the compiled module, or the bytes of runtime/mhfe.wasm
  argon2Threaded, // text of core/argon2-mt.js
  argon2SingleThreaded, // text of core/argon2-st.js
});

const sealed = await client.encrypt({
  phrase,
  password,
  passwordRepeat, // the password typed a second time; a difference is refused
  sameLength: false, // true only when the user has chosen a container of the phrase's length
  repairWordCount: 4, // 0 (the default) for none, or 2, 4, 6 or 8
  walletHasPassphrase, // optional: true or false only where the page knows it
  onProgress: ({ stage, round, rounds }) => showProgress(stage, round, rounds),
  // After 12 of the 24 rounds: show it, marked as not yet verified, while the check runs.
  onUnverified: ({ container, containerFingerprint }) => showUnverified(container),
});
// Resolved only after the check has passed; a failed check rejects with VERIFICATION_FAILED.
// sealed: { container, suiteId, containerFingerprint, builtInCheck, otherLengths, repairWords,
//           repairProfile, keep: [{ item, ... }] }

const recovery = await client.decrypt({
  container,
  password,
  passphrase, // the wallet's BIP39 passphrase for the 16-bit source check; "" (the default): none
});
// recovery.kind is "phrase" or, very rarely, "ambiguous"; show every candidate then. Each
// candidate: { words, verified, status, phrase, suiteId, fingerprintWithoutPassphrase,
//              walletCheck, statedWords, otherLengths }; status is "verified", "noBuiltInCheck",
//              "readAs24" or "readAs24Chosen".

// The first receiving address of the public BIP84 test wallet, whose phrase is "abandon" eleven
// times and then "about". `coin` is required, an id of MhfeWallet.parameters().coins: no coin is
// the default, so that a page for one coin names no other. "ethereum" covers every EVM network.
// `coin` and `path` belong only to an address: with another reference they are a TypeError.
const { matches, path, evidence } = await client.check({
  container,
  password,
  reference: { address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", coin: "bitcoin" },
});
// For a container of that phrase: matches is true and path is "m/84'/0'/0'/0/0", where the
// address was found. Without a match, and for the other references, path is null.
// evidence: { builtInCheck, walletCheck }, the original seed phrase's own checks.
```

`pim` and `memoryLevel`, 0 by default, are the container's settings: `encrypt()`, `decrypt()`,
`check()`, `searchWallet()`, `openHiddenWallets()` and, for the old container, `rekey()` take them.
Wherever a password is typed, `passwordRepair` is the choice of its check word review (see
[Passwords](#passwords)).

`walletHasPassphrase` says whether the wallet of the phrase has a BIP39 passphrase. MHFE encrypts
the phrase, not the passphrase, so a wallet with one still needs it: with `true` the result's
`keep` names it, and with `false` it does not. Pass it only where the page knows the answer without
asking, such as for a phrase it has just drawn with `drawPhrase()`. Left out or `null`, `keep` names
any passphrase of the wallet, `{ item: "passphraseIfAny" }`, in its place, as `mhfe encrypt` does,
which does not ask; any other value is a `TypeError`. `keep` lists what the owner keeps, in this
order: `{ item: "containerWords", words }` and `{ item: "password" }` always, then
`{ item: "passphrase" }` or `{ item: "passphraseIfAny" }` where it applies, and only where needed
`{ item: "repairWords" }`, `{ item: "pim", value }`, `{ item: "memoryLevel", value }` and
`{ item: "wordCount", words }`.

`decrypt()` takes `words`, 0 (the default) to detect the length or the length the user knows, and
`passphrase`, the wallet's BIP39 passphrase, "" (the default) for none. Each candidate says what
the page shows with the phrase:

- `walletCheck` says whether a 24-word reading passes the 16-bit source check with `passphrase`,
  and is null for every other length. Every recovery evaluates it: the container does not show
  whether the phrase was made with the check, so a page asks for the passphrase when a 24-word
  reading comes out and decrypts again with it, or asks before. A pass makes a right password very
  likely; a failure means something only if the wallet was made with the check.
- `statedWords` is the length stated where a built-in check that passes gave the reading another
  length, which takes precedence: the page says so. It is null when the reading has the length
  stated or none was stated. 24 stated words beside a check that passes give `"ambiguous"`, the
  checked reading first.
- `otherLengths` lists the other 12- to 21-word lengths whose built-in check passes too, by chance.

`readPhrase()` and `readContainer()` read words the way a person may have typed them and give them
back written out, with what the page needs to know about them: the containers a phrase can go into
and what each means, and for a container the lengths its phrase can have, what confirms a recovery
of each, and whether hidden wallets and the wallet check apply. `parameters()` gives the fixed
values, such as the repair word counts and what each repairs.

`check()` takes exactly one reference: `{ address, coin, path? }`, `{ fingerprint }`, `{ words }`,
the built-in check of a 12- to 21-word original seed phrase, or `{ walletCheck: true }`, the phrase
and passphrase check, with the wallet's `passphrase`. The wallet check compares the container's
24-word reading only, never a shorter one, as the profile defines it. Some references cannot apply,
and these are refused before the first round (the worker runs only the small known answer of its
Argon2 build first). A same-length container has no built-in check (`NO_BUILT_IN_CHECK`) and no
wallet check (`NO_WALLET_CHECK`). On a 24-word container the wallet check without a passphrase is
refused with `WALLET_CHECK_NEEDS_PASSPHRASE`. `readContainer()` says which apply
(`builtInCheckLengths`, `offersWalletCheck`).

`evidence` is what the same recovery shows of the original seed phrase's own checks:

- `builtInCheck` is the 12- to 21-word length whose built-in check passes, the stated one where it
  passes, or null. With `{ words }`, a check that passes at another length takes precedence and
  matches, and `builtInCheck` names that length: say so, as the command-line tool does.
- `walletCheck` says whether the 24-word reading passes the 16-bit phrase + passphrase check with
  the `passphrase` given, or with none if none was given. It is null for `{ words }` with a length
  stated, for a same-length container, and when exactly one shorter length passes its check and the
  reference did not match the 24-word reading. A phrase drawn without that check fails it, so only
  a pass says anything.

`{ words: 0 }` detects the length: the built-in check of whichever 12- to 21-word length passes it,
or with a `passphrase`, the phrase + passphrase check of a 24-word phrase drawn with it. Ask the
user whether a BIP39 passphrase is used with the original seed phrase first. When detection finds
no length, `onNoLength` is called: ask how many words the original seed phrase has, and return
`{ words }` for 12 to 21 words, which then does not match, or for 24 words
`{ address, coin, path?, passphrase? }` or `{ fingerprint, passphrase? }`, compared on the same
recovery without its rounds again; `null` keeps the result. `onNoLength` with another reference is
a `TypeError`.

```js
const resealed = await client.rekey({
  container,
  words: 24, // the phrase's word count; 0, the default, detects it
  password,
  pim, // the old container's settings, 0 by default
  memoryLevel,
  newPassword,
  newPasswordRepeat,
  newPasswordRepair, // the check word review's choice for the new password
  newPim, // the new container's settings, 0 by default; memory level 0 only in a browser
  newMemoryLevel,
  repairWordCount: 4, // repair words of the new container, as for encrypt()
  // Or { builtInCheck: true }, { fingerprint } or { owner }.
  confirmation: { address, coin: "bitcoin" },
  passphrase, // the wallet's BIP39 passphrase, only with an address or a fingerprint
  walletHasPassphrase, // the user's answer; may be left out only when passphrase is not empty
  onProgress, // as for encrypt(), over 36 rounds
  onUnverified, // as for encrypt(): the new container before its check
});
// resealed: what encrypt() gives, and walletCheck
```

`rekey()` encrypts a container again with a new password or settings, in 36 rounds. It recovers the
phrase with the old password, confirms it and seals it again in a container of the same kind. The
result is that of `encrypt()` with `walletCheck`: whether the recovered 24-word reading passes the
16-bit source check with the reference's `passphrase` or none, null for other lengths. Every
recovery reports it, and it never confirms a rekey.

- `words` is the phrase's word count, or 0, the default, to detect it. For a same-length container
  it is 0 or the container's own length. With the length detected on a 24-word container
  (`confirmationFor["0"]` is `"walletOrOwner"`), `{ builtInCheck: true }` alone is refused with
  `REFERENCE_REQUIRED` before the first round (only the 1 MiB known answer of the Argon2 build runs
  first, as for `check()`): a 24-word original may pass a short check by chance and would be sealed
  again as another wallet. An address or the fingerprint is compared with every reading and
  confirms the one it matches, whatever its length; the owner confirms the one reading found.
- Several lengths that pass by accident, about once in four billion containers, reject
  `{ builtInCheck: true }` and `{ owner }` with `AMBIGUOUS_LENGTH`, unless the owner's stated
  length is one of them: rekey again with an address or the fingerprint, which compares every
  reading, or with the owner and the length of the reading to compare stated. A stated length that
  the built-in check contradicts rejects `{ builtInCheck: true }` with `LENGTH_DIFFERS`: rekey again
  with an address, the fingerprint or the owner. `{ owner }` beside 24 stated words is rejected
  with `LENGTH_DIFFERS` too when one 12- to 21-word length passes its check: the owner cannot tell
  the two readings apart, and only an address or the fingerprint confirms one. A stated 12- to
  21-word length whose built-in check fails, with no other length passing, rejects with
  `VERIFIER_MISMATCH` whatever the confirmation, before any reference is compared: the password, a
  setting or the stated length is wrong.
- Each of these refusals ends the rekey: a page calls `rekey()` again, which recovers again in 12
  rounds. After `AMBIGUOUS_LENGTH` or `LENGTH_DIFFERS` the command-line tool asks again on the same
  recovery instead, as listed
  [further down](#what-the-command-line-tool-has-and-the-browser-does-not).
- `confirmation` is one of four kinds; `readContainer().confirmationFor` says which a length needs.
  A length with a built-in check takes `{ builtInCheck: true }`, or a receiving address
  `{ address, coin, path? }`, the fingerprint `{ fingerprint }` or the owner,
  `{ owner: (check) => boolean | Promise<boolean> }`, which any other length needs.
  `{ builtInCheck: true }` there is refused with `REFERENCE_REQUIRED`, before a missing or
  contradicting `walletHasPassphrase` is judged (a value of the wrong type is refused even
  earlier), and a reference that does not match with `REFERENCE_MISMATCH`.
- The owner callback receives `{ phrase, words, statedWords?, fingerprintWithoutPassphrase }` to
  compare with the written backup. `statedWords` is there only where the built-in check found
  `words` instead of the length stated: say so before the owner compares, as the command-line
  tool does. The rekey waits for its answer; anything but `true` stops it with
  `NOT_CONFIRMED_BY_OWNER`, and the library seals nothing before that yes. Offer `{ owner }` only to
  a user who knows neither a receiving address nor the fingerprint, as the specification allows
  it only then, and ask for the answer with nothing preselected. For a phrase without a built-in
  check (`words` 24, or a same-length container), keep a fingerprint of the confirmed phrase for
  the rehearsal of the new container before sealing: `fingerprintWithoutPassphrase`, or
  `MhfeWallet.fingerprint()` with the wallet's passphrase.
- `walletHasPassphrase` says whether the wallet has a BIP39 passphrase, so that the new
  container's `keep` names it, as after `encrypt()`. Only an address or a fingerprint compared with
  a `passphrase` that is not empty shows that the wallet has one: there the answer may be left out,
  and `false` is refused with `INVALID_REQUEST`. Everywhere else the answer is required
  (`INVALID_REQUEST` without it): `{ builtInCheck: true }` and `{ owner }` show nothing of a
  passphrase, and an address or a fingerprint with an empty `passphrase` matches the phrase's
  wallet without one, which proves nothing about funds under a passphrase, so it confirms only a
  wallet stated to have none: `true` is refused there with `INVALID_REQUEST`, as a wallet with a
  passphrase is compared with it. These refusals come before the first round. The client takes
  `true`, `false` or `undefined`; any other value, `null` included, is a `TypeError`.
- `passphrase` belongs only to an address or a fingerprint: one that is not empty with
  `{ builtInCheck: true }` or `{ owner }` is a `TypeError`, and the types in `core/client.d.ts`
  allow no `passphrase` there at all. For an address or a fingerprint they take either a
  `passphrase`, with `walletHasPassphrase` optional, or no `passphrase` and `walletHasPassphrase`
  required. A type cannot tell an empty `passphrase`: without the answer it is refused when the
  rekey runs (`INVALID_REQUEST`).
- The wallet check (16 bits) and a word count never confirm a rekey: `{ walletCheck }` and
  `{ words }` are a `TypeError` here.
- A new password and settings that would give the old container again are refused with
  `NEW_PASSWORD_SAME_AS_OLD`, before the first round.

```js
const session = await client.openHiddenWallets({ container, mainPassphrase }); // "" for none
const wallet = await session.open({ password, passwordRepeat });
// wallet: { phrase, words, fingerprintWithoutPassphrase }
await session.close();
```

`openHiddenWallets()` opens a session of hidden wallets on a 24-word container. It resolves once the
session has reserved its Argon2 work area. Each `open()` gives the wallet of a new password, typed
twice, in 12 rounds.

- A password used already (`PASSWORD_ALREADY_USED`), one whose wallet would pass a check
  (`HIDDEN_WALLET_PASSES_CHECK`) and a password refused before any work reject that `open()` only.
  The session stays open.
- A second `open()` while one runs is refused with `BUSY`, and an `open()` after the session has
  ended with `SESSION_CLOSED`.
- `close()` returns a promise. While the session waits for the page, the worker frees it: the Rust
  code overwrites its passwords and passphrase, and the promise resolves once the worker has ended.
  During an `open()` it stops the worker at once instead, which frees the memory without
  overwriting it, and that `open()` rejects with `MhfeCancelledError`.
- The session holds the core's slot for long operations until it ends.

`selfTest()` runs the published vectors at their full cost. It encrypts the suite 3 vector, then
recovers the suite 4 vector, and resolves to `{ passed, suite3, suite4, firstWrongRound, fault }`,
`suite3` and `suite4` each `{ vector, asPublished }` (see
[The published vectors](#the-published-vectors)).

### Repair words

```js
import { MhfeRepair } from "./repair/repair.js";

const repair = new MhfeRepair({ workerSource, wasm }); // the same worker and WebAssembly
const card = await repair.repairWords({ container, count: 4 }); // 2, 4, 6 or 8 words
// card: { profile, words, repairsUnreadable, repairsWrong }

// The container phrase and the card as read, "?" for a word that cannot be read.
const repaired = await repair.repairContainer({ container: containerAsRead, card: cardAsRead });
// repaired: { container, containerFingerprint, unchanged, containerWords, cardWords, changes }

// What a container phrase as typed is, before a page decrypts, checks or repairs it.
const { reading, wordCount, unreadable } = await repair.inspectContainer({ container: typed });
// reading: "container", "marked" (words typed as "?"), "notAContainer" or "wrongLength"

// Without the repair words: the candidates, then the decoy wallet, the container itself, in
// seconds for one missing word and minutes for two, and only then the owner's wallet, a full
// recovery a candidate.
const { missing, candidates, offersWalletSearch, offersOwnChecks } = await client.searchCandidates({
  container: typed,
});
// The answers offered come from the library: the wallet search for one missing word, and the
// original seed phrase's own checks where the container carries them, as the command-line tool.
const fast = await client.searchDecoy({ container: typed, reference: { fingerprint }, passphrase });
// For two missing words and an address: scanGap, the first-account addresses of each chain
// searched, parameters().decoyScanGap (20) by default; ask the user, as the command-line tool
// does, when the wallet may go on.
const slow = await client.searchWallet({ container: typed, password, reference: { fingerprint } });
// reference also { address, coin, path? }; for searchWallet the original seed phrase's own
// checks: { walletCheck: true } with its BIP39 passphrase, or { builtInCheck: true } without.
// { found, container, containerFingerprint, words: [{ position, word }], path, candidates }
```

### Passwords

```js
import { MhfePasswords } from "./passwords/passwords.js";

const passwords = new MhfePasswords({ workerSource, wasm });
const review = await passwords.review({ password: typed });
// review.reading: "notThisShape", "fits", "restorable" or "mismatch", with the repairs offered.
// The user's choice goes to the long operation as passwordRepair: "asTyped", "corrected" or
// { repair: position }.
const { bits, weak } = await passwords.strength({ password: typed, passwordRepair: choice });

const made = await passwords.make(); // five words, as `mhfe password` makes
// made: { password, bits, weak, checkWord }, bits a number such as 64.625
```

`review()` of a new password takes it twice, `{ password, passwordRepeat }`, checks the
password's own rules and then compares the two entries, in the order the command-line tool does:
a difference is `PASSWORDS_DIFFER`, and so is an empty `passwordRepeat`. Without `passwordRepeat`
the password was typed once, as for an existing container. `encrypt()`, `rekey()` and a hidden
wallet's `open()` check a new password the same way.

`make()` makes words by default: five words, or `count` words from 1 to 32.
`{ kind: "characters" }` gives 16 characters, or `count` from 1 to 64, and `{ kind: "checkWord" }`
gives five words and their check word. `"checkWord"` takes no `count`, as `mhfe password` refuses
`--check-word` with `--words`: a `count` other than `undefined` rejects with a `TypeError` before
any worker starts, so that a page never gets another number of words than it asked for. With `dice`,
five digits from 1 to 6 per word in groups separated by spaces, the words come from real dice: one
group per word, five for `"checkWord"`. A character password cannot come from dice
(`INVALID_REQUEST`).

### Wallet

```js
import { MhfeWallet } from "./wallet/wallet.js";

const wallet = new MhfeWallet({ workerSource, wasm });
// "73c5da0a" for the public BIP39 test phrase ("abandon" eleven times, then "about") without a
// passphrase.
const fingerprint = await wallet.fingerprint({ phrase, passphrase }); // passphrase may be ""
const passes = await wallet.walletCheck({ phrase, passphrase }); // 24 words and a passphrase
const scope = await wallet.describeAddress({ address, coin: "bitcoin" }); // shown before a check
// With scanGap, the decoy search of two missing words: the first account, scanGap of each chain.
const decoyScope = await wallet.describeAddress({ address, coin: "bitcoin", scanGap: 20 });
// A chosen word, at a position from 1 to 24 or "anywhere", and a word never to use (not
// recommended): what they leave of the phrase's randomness, shown before the draw.
const chosen = [{ word: "zoo", position: 24 }];
const neverUse = ["abandon"];
const cost = await wallet.describeDraw({ chosen, neverUse, walletCheck });
// cost: { randomBits, randomness, expectedDraws, recognisable, fixedPosition }
const drawn = await wallet.drawPhrase({
  passphrase, // "" for a wallet without one
  passphraseRepeat, // the passphrase typed a second time; a difference is refused
  walletCheck, // the user's answer, never preselected; true needs a passphrase
  chosen, // optional
  neverUse, // optional
  onProgress: ({ draws }) => showDraws(draws),
});
// drawn: { phrase, words, walletCheck, fingerprintWithPassphrase, workers }
```

`fingerprint()` and `walletCheck()` read the phrase as every other method does, in any letter case
and spacing and with the first four letters of a word. `walletCheck()` takes a 24-word phrase and a
passphrase that is not empty (`INVALID_WORD_COUNT`, `WALLET_CHECK_NEEDS_PASSPHRASE` otherwise).

`drawPhrase()` draws a new 24-word phrase from the browser's random generator. A passphrase must be
typed twice (`PASSPHRASES_DIFFER` otherwise), and `walletCheck` must then be `true` or `false`.
`walletCheck: true` without a passphrase is refused with `WALLET_CHECK_NEEDS_PASSPHRASE`. A phrase
with the wallet check takes about 65,536 draws. They are spread over `workers` workers, by default
as many as the processor has cores, at most eight; a page may ask for 1 to 256. One phrase is drawn
at a time (`BUSY` otherwise), and `wallet.cancel()` stops it.

`chosen` holds at most `parameters().maxChosenWords` (1) word for the new phrase, `{ word, position
}` with `position` from 1 to 24 or `"anywhere"`, and `neverUse` at most
`parameters().maxNeverUseWords` (1) word it must not hold. Choosing a word is not recommended
(README, "Chosen words") and is a feature of this program, not of the specification. The chosen
word is part of the secret phrase: it reaches the worker as bytes that it wipes, and no refusal
names it. A word outside the English list, a second word of either kind or a chosen word also never
to use is refused with `INVALID_WORD_WISH`. The phrase is drawn until it meets both wishes, so every
phrase that meets them is equally likely. `describeDraw()` says first what they cost, as the
command-line tool states it before it draws: `randomBits`, the random bits the phrase keeps for
someone who knows the word, about, the check's 16 included, at least 228.98 with the check and
244.98 without; `randomness`, `"full"` for all 256, `"ample"` from
`parameters().recommendedRandomBits` (240, what the check alone leaves: still far more than enough)
and `"notRecommended"` below it, rated without the word never to use, whose 0.016 bits do not
matter; `expectedDraws`; `recognisable`, true with a chosen word, which lets someone who learns or
guesses it rule out almost every wrong MHFE password and tell the wallet from a decoy; and
`fixedPosition`, true when the chosen word has a position. A page shows a warning for anything but
`"full"`, and another for `recognisable`, as the command-line tool does, which adds for a word at a
fixed position that a word anywhere keeps more.

`wordHints({ typed })` gives the hint below a line of BIP39 words being typed, a seed phrase, a
container phrase, repair words or a chosen word, by the command-line tool's rule (owner,
2026-10-08): `{ hint, count, words, completion: { letters, wordEnds } }`. For the last word of the
line, `hint` is `"count"` after one letter, with how many words begin with it; `"words"` from two
letters, with those words in list order; `"noWord"` when none does; and `"nothing"` when no word of
letters is being typed or the word is whole with no longer word after it. `completion` is what Tab
adds: the letters all those words share next, and whether one word is left, which then ends with a
space. `MhfePasswords.wordHints()` gives the same for the words of the EFF list in a password; a
password may hold any text, so a page shows nothing for `"noWord"` there and keeps Tab a character
of the password. The line reaches the worker as bytes that it wipes. Each call starts a worker, so
a page may ask once typing pauses. The lists are public: a hint tells nothing that someone who sees
the screen could not look up, but it is shown only where the typed text itself is shown.

## Progress, cancelling and errors

Long operations report `onProgress({ stage, round, rounds })` as each round starts:

| Operation            | Rounds         | Stages                                                                   |
| -------------------- | -------------- | ------------------------------------------------------------------------ |
| `encrypt`            | 24             | "encrypt" 1 to 12, then "check" 13 to 24                                 |
| `decrypt`            | 12             | "recover"                                                                |
| `check`              | 12             | "recover", then "compare" once before the comparison with the reference  |
| `rekey`              | 36             | "recover" 1 to 12, "compare" with a wallet reference, "encrypt", "check" |
| hidden wallet `open` | 12             | "recover"                                                                |
| `selfTest`           | 24             | "encrypt" 1 to 12, then "recover" 13 to 24                               |
| `searchWallet`       | 12 a candidate | "search"                                                                 |
| `searchDecoy`        | none           | "search"                                                                 |

The searches for missing words report `{ stage: "search", candidate, candidates }` instead:
`searchDecoy()` at the first candidate, every 64th and the last, and `searchWallet()` with `round`
and `rounds` of the candidate's recovery as each of its rounds starts.

A new phrase reports `{ stage: "draw", draws }` instead: the draws of all its workers together,
after every 1,024 draws of each, so in practice only a phrase with the wallet check, which takes
about 65,536 draws, reports any.

Each operation runs in a new worker, which is terminated when the operation ends; this also frees
the 2 GiB of Argon2 memory. A worker that is still loading the WebAssembly when its operation ends
is terminated as soon as it has loaded it, or after the minute a start may take: Firefox crashes
the whole page when a worker is terminated while it loads the WebAssembly. `client.cancel()` stops
the running long operation or session, and `wallet.cancel()` a phrase being drawn: its promise
rejects at once with `MhfeCancelledError`, code `CANCELLED`, and its worker is terminated as just
described. The core runs one long operation or session at a time (`BUSY` otherwise); its
parameters and reading words never wait. The other modules run every call in a worker of its own,
and their calls never wait for each other; only `MhfeWallet` draws one new phrase at a time.

Every method returns a promise and reports every error by rejecting it, also a refused argument
such as an empty password or a PIM out of range: `await` inside `try` and `.catch()` both see all
of them. A wrongly typed argument rejects with a `TypeError`, except a number of the core's
settings and lengths, which rejects with its own code (`INVALID_PIM`, `INVALID_MEMORY_LEVEL`,
`INVALID_WORD_COUNT`, `INVALID_REPAIR_WORDS`); every other error is an `MhfeError`
with a `code` and an English `message` that a page can show as it is. A password and its
repetition are checked for their type before they are compared, so two values of a wrong type are
a `TypeError`, not `PASSWORDS_DIFFER`. A secret that may be left out, such as a repetition or a
BIP39 passphrase, is empty only when it is left out (`undefined`): `null` is a `TypeError` too, not
an empty secret. `MhfeErrorCode` in
`runtime/runtime.d.ts` lists every code. `mode()`, `maxSupportedMemLevel()` and both `cancel()`
methods are synchronous and return at once.

If a callback of the page throws, or is async and its promise rejects while the operation runs, the
operation stops, its worker ends and the promise rejects with `CALLBACK_FAILED`, the page's error
as its `cause`. A failing `onProgress` of a hidden wallet ends the whole session, and one of a new
phrase stops every worker of the draw. The client does not wait for a callback's promise, except
for the owner's answer in a rekey and the answer of `check()`'s `onNoLength`, which it awaits.

## Self-checks

Every class checks its parts on the page before its first operation, so that a broken build, files
of different builds, a damaged file that changes an answer or a browser that computes something
wrongly shows before anything secret is typed. The checks are those of the command-line tool, run by
the same Rust code: each compares exact output with published test vectors, or with values from an
independent implementation that first reproduced a published vector, and gives every verifier a case
it must refuse, such as a card of another container phrase, six words that do not fit their check
word or a damaged address. They use public test data only, in a worker of the class, and load
nothing. The same parts with their slower cases make the full self-test; the published MHFE vectors
at their full cost stay in `selfTest()`. The repository's
[`docs/API.md`](https://github.com/hobby-eng/mhfe/blob/main/docs/API.md#self-checks) lists what each
part compares.

### Before first use

```js
const wasm = await WebAssembly.compile(mhfeWasmBytes); // once, for every class
const repair = new MhfeRepair({ workerSource, wasm });
const report = await repair.startupCheck();
// { passed, tier: "startup", version, buildId, components: [{ id, label, outcome, detail? }] }
if (!report.passed) showFailedSelfTest(report); // keep the class's controls closed
```

`startupCheck()` resolves to a report: `outcome` is "passed", "warning", "notAvailable", "notRun"
or "failed", and `passed` is false only when a part failed. A detail names a case by its place and
what differed, such as "card 1 of 1 gives other words", and never holds a secret, a coin's name, an
address or a vector's text; no label names a coin either. The page's own parts come first:

- `browser-features`, "Browser features": WebAssembly, workers, Blob URLs and `TextEncoder`;
  `crypto.getRandomValues` for `MhfePasswords` and `MhfeWallet`; `SharedArrayBuffer` and `Atomics`
  for `MhfeClient` on a cross-origin isolated page; and a WebAssembly that compiles here, which it
  does not under a Content-Security-Policy without `'wasm-unsafe-eval'`;
- `package-parts`, "Package parts": the class file and `runtime/runtime.js` of one build;
- `page-encoding`, "Text encoding of the page", for the classes that take secrets (`MhfeClient`,
  `MhfePasswords`, `MhfeWallet`): the UTF-8 bytes of the password of the published vector
  unicode-password, and the refusal of a lone surrogate.

The class's own parts follow, run in its worker:

- `MhfeClient`: `cipher-hashes`, `argon2`, `cipher-rounds`, `formats`, `container-facts`,
  `keep-advice`, `password-unicode`, `bip39-words`, `repair-words`, `container-search`,
  `password-check-word`,
  `wallet-hashes`, `bip39-seed`, `bip32`, `addresses`, `wallet-check`, `hidden-wallets`, `rekey`
  and `rehearsal`;
- `MhfeRepair`: `bip39-words` and `repair-words`;
- `MhfePasswords`: `password-unicode`, `password-check-word`, `password-generator`, `word-hints`
  and `random-source`;
- `MhfeWallet`: `bip39-words`, `wallet-hashes`, `bip39-seed`, `bip32`, `addresses`,
  `address-search`, `wallet-check`, `word-wishes`, `word-hints` and `random-source`;
  `address-search` compares what `describeAddress()` states with known answers, through the same
  library call, and `word-wishes` draws six phrases with chosen words from a scripted source,
  compares them and the draw each takes with an independent implementation's, and sets, reads and
  filters a word at every position against an independent oracle.

None of them needs Argon2 except `argon2`. `MhfeClient.startupCheck()` runs Argon2's known answer
at 1 MiB through the Argon2 build of the page's mode, which it loads for this.
`startupCheck({ argon2: false })` leaves Argon2 out and lists it as not run ("this check leaves
Argon2 out"): a page runs it at its start without loading Argon2, since every Argon2 operation
checks its build itself (see [Every Argon2 operation](#every-argon2-operation)). At start the
random source is checked with scripted bytes only; the browser's generator is not called.

An Argon2 build that does not start, as when the browser refuses its memory or its lane workers,
gave no wrong answer, so it closes nothing. When no build starts, the Argon2 parts are
"notAvailable" with the cause, such as "Argon2id could not run: the single-threaded Argon2 build
did not start: …". In fast mode the check also loads the single-threaded build of the standard
mode: when only the threaded build does not start, `argon2` is checked with the single-threaded
one and passes as a "warning", "the threaded Argon2 build did not start: …; the check ran the
single-threaded build of the standard mode instead". A wrong answer of that build still fails,
with the same note before its detail. An operation still uses its mode's build and, when it does
not start, rejects with its own error.

Every other method of a class awaits a startup check before its first call, and starts one when none
has run: `MhfeClient` without Argon2. Not awaited are `fullCheck()` and `parameters()` of every
class and, of `MhfeClient`, `mode()`, `maxSupportedMemLevel()`, `cancel()` and `selfTest()`, and
`cancel()` of `MhfeWallet`. Secrets are copied into bytes only after the check has passed. While a
long operation of the core or a new phrase waits for the check, the class is busy (`BUSY`) and
`cancel()` stops the wait.

A report is made once for each class and choice, and every call shares it, except a report with a
part that is "notAvailable" or a "warning", which at start only an Argon2 build that did not start
gives: it passes but is not kept, and the next call checks again. A part that another class has
passed with the same WebAssembly object is not run again and appears in the report as that class
found it: a page that compiles `runtime/mhfe.wasm` once and passes the module to every class checks
a shared part, such as the BIP39 word list, once. Argon2's part counts only for the Argon2 build
that gave it. In Chromium and Firefox a class's startup check, the start of its worker included,
took from about 15 to 210 milliseconds, the wallet's and the core's the longest.

### The full self-test

`fullCheck({ onProgress })` of a class runs every part again, with its slower cases, and without
leaving out what another class has passed: the parts listed in the repository's
[`docs/API.md`](https://github.com/hobby-eng/mhfe/blob/main/docs/API.md#self-checks)
with their full-tier cases, and for `MhfePasswords` and `MhfeWallet` the browser's random
generator, two probes and the spread of 1,024 of its bytes. `onProgress` receives
`{ id, label, running: true }` as a part of the worker starts and
`{ id, label, outcome, detail?, running: false }` as it ends. It resolves to a report like that of
`startupCheck()`, with `tier` "full".

`MhfeClient.fullCheck()` then checks Argon2 at 64 and 256 MiB with the single-threaded build,
`argon2-sizes-single-threaded`, "Argon2id at 64 and 256 MiB, single-threaded build", and on a
cross-origin isolated page with the threaded build after it, `argon2-sizes-threaded`, "Argon2id at
64 and 256 MiB, threaded build": never both at once, each in a worker of its own. In standard mode
the threaded part is not run, "the page is not cross-origin isolated". A browser that cannot give
the memory, or an Argon2 build that does not start, makes such a part not available rather than
failed. Last, the report lists what the
command-line tool's self-test has and a page does not run:

| Id                  | Label             | Outcome        | Detail                                                                |
| ------------------- | ----------------- | -------------- | --------------------------------------------------------------------- |
| `published-vectors` | Published vectors | "notRun"       | they take minutes and 2 GiB: selfTest() runs them                     |
| `memory-locking`    | Locked memory     | "notAvailable" | a web page cannot keep its memory out of swap                         |
| `core-dumps`        | Core dumps        | "notAvailable" | the browser keeps its own crash reports, which a page cannot turn off |
| `isolation`         | Isolation         | "notAvailable" | a web page cannot sandbox itself or prove that it is offline          |
| `hidden-input`      | Hidden input      | "notAvailable" | a web page has no terminal whose echo it could read back              |

In Chromium and Firefox `MhfeClient.fullCheck()` took one to two and a half seconds, with up to
256 MiB for one Argon2 build at a time; the full checks of the other classes take a fraction of a
second.

### The published vectors

`selfTest()` encrypts the suite 3 vector zero-12 and recovers the suite 4 vector
same-length-zero-12 at their full cost, 2 GiB and 12 rounds each, and compares the results with the
published ones. It takes minutes, so it is never part of a startup check or of `fullCheck()`,
which lists it as not run; a page starts it only when the user asks. It finds faults that appear
only at Argon2's full size. Of its 24 rounds, 1 to 12 are the encryption and 13 to 24 the recovery.
`fault` is `null` when the test passed, else `{ kind, round, message }`, which says where the work
first left the published path:

- "argon2-input": in round `round`, Argon2id was given an input, password or salt, that the
  published vector does not have there, so the fault lies before Argon2id, in that round's password
  or salt or in the state the round started from;
- "argon2-key": in round `round`, the published input gave another key, so the fault lies in
  Argon2id;
- "after-argon2", `round` `null`: every Argon2id input and key was as published, so the fault lies
  after the last Argon2id call of the encryption or the recovery.

`message` is the sentence the command-line tool shows, such as "first wrong round 4 of 24: Argon2id
returned another key for the published input, so the fault is in Argon2id". `firstWrongRound` is
`fault.round`: the round where Argon2id's input or its key first differed, or `null`.

### Every Argon2 operation

Every operation that runs Argon2 (`encrypt`, `decrypt`, `check`, `searchWallet`, `rekey`, the
`open` of a hidden wallet, and `selfTest`) computes Argon2's known answer at 1 MiB through its
Argon2 build before its first round and again after its last; a session of hidden wallets also
when it starts. A different answer rejects with `SELF_CHECK_FAILED` ("The self-test failed:
Argon2id: …"), in place of the operation's own error if it had one, and the result is dropped. The
answer after the last round also covers the optimized code that a browser makes of a long-running
loop. Every round also refuses a key that the build left unwritten or set to zeros
(`ARGON2_FAILED`).

### When a check fails

- A part that fails closes its class for good. Every method that awaits the check then rejects
  with `SELF_CHECK_FAILED`, and the error's `report` is the report; its message is
  `The self-test failed: <label>: <detail>. Do not use this program on this computer`. A failed
  `fullCheck()` closes the class too.
- A part in which the WebAssembly stopped, by a Rust panic or a fault of the computer, fails with
  the detail "the WebAssembly stopped".
- Files of different builds give `PACKAGE_MISMATCH` instead of a report, with a message that names
  the two files, as the package spells them, and their builds, such as "The file core/argon2-st.js
  is of build … and runtime/worker.js of build …: take every file of the package from one build.";
  so does a `core/client.js` whose limits differ from the WebAssembly's.
- A worker that does not start gives `WORKER_FAILED`, for example "The worker did not start within
  a minute.".
- Neither `PACKAGE_MISMATCH` nor `WORKER_FAILED` closes the class: the next call checks again.
- An Argon2 build that does not start makes the Argon2 parts not available, or in fast mode a
  warning when the single-threaded build ran instead (see [Before first use](#before-first-use)).
- A warning, a part not available here and a part not run are not failures; `passed` stays true.

### What a browser cannot check

- Locked memory, core dumps, isolation and hidden input: the web platform offers a page no way to
  lock memory, turn off or read back crash reports, sandbox itself, prove that it is offline or
  read back a terminal's echo. `MhfeClient.fullCheck()` lists them as not available, with these
  reasons.
- Argon2 at 2 GiB inside `fullCheck()`: the published vectors take minutes and 2 GiB, so they run
  only when the user asks, in `selfTest()`. The answer after the last round of each operation
  narrows faults that the browser's optimized code shows only in long rounds, but only
  `selfTest()` covers the full size.
- Memory levels above 0, which a browser does not support. Their rounds are still replayed by
  `cipher-rounds` with the keys the published vectors record.
- The RFC 9106 Argon2 vector, which sets a secret and associated data: the browser's Argon2 builds
  export only `argon2id_hash_raw`, which has neither. The page compares OpenSSL's tags at 1, 64 and
  256 MiB instead.
- That Argon2 wiped its memory after a call: where the allocator put the freed work area in the
  Emscripten heap is not reliably known, so the page does not scan for it. The package's Node
  checks (`scripts/verify-browser-package.mjs`) confirm it for the single-threaded build: about
  2 KiB of allocator records and of the stack of the last block computation stay non-zero after a
  1 MiB call.
- The threaded Argon2 build on a page that is not cross-origin isolated, such as one opened as a
  file: without `SharedArrayBuffer` it cannot run, and its part is not run.
- Free memory, which a page cannot measure (see [Memory](#memory)).
- A random generator that is deterministic but looks random: no test can tell. The checks find one
  that is stuck or narrow.
- Deliberate tampering: the build identifier catches files of different builds mixed by accident.
  Tampering is for `SHA256SUMS` and its OpenPGP signature, the build attestations and, in fast
  mode, the page's `mhfe-fast-mode.sha256`.

## Fast and standard mode

`client.mode()` returns `"fast"` when the page is cross-origin isolated and `"standard"` otherwise.
In fast mode the four Argon2 lanes run in parallel threads: a recovery takes about one and a half to
two minutes. In standard mode they run one after another, about four to seven minutes. An encryption
takes about twice as long in either mode. The measurements behind these figures are in
[`docs/measurements/`](https://github.com/hobby-eng/mhfe/blob/main/docs/measurements/README.md).

A page opened as a file is never isolated. `mhfe serve <page.html>` serves it from this computer
with the headers that make it isolated. On a computer without the mhfe program, the package's own
launcher, `core/mhfe-fast-mode.py`, does the same with Python 3.8 or later and nothing else.

Both launchers serve a page only when the checksum file `mhfe-fast-mode.sha256` lies next to it: one
line in the format `sha256sum` writes, the page's SHA-256, two spaces and its file name, or one
space and `*` before the name as `sha256sum --binary` writes it. Ship that file beside the tool's
HTML file, always under this name. Without it, with another file name in it or with a different
SHA-256, the launcher refuses with a message and serves nothing. Started without arguments, as by a
double-click, `mhfe` shows its menu, whose first entry serves the page named in the
`mhfe-fast-mode.sha256` next to the program; when that file is wrong, the menu says that the fast
mode is not offered, and why. `mhfe-fast-mode.py` started without arguments serves that page at
once. `mhfe serve <page.html>` and `python3 mhfe-fast-mode.py <page.html>` serve a page elsewhere,
next to its own checksum file. A page whose own launcher sends these headers does not need either.

## Memory

A browser gives WebAssembly at most 4 GiB, and the reference Argon2 code allows 2 GiB on 32-bit
targets, so the browser supports memory level 0 only. `client.maxSupportedMemLevel()` returns 0. A
higher level, also as the new level of a rekey (`newMemoryLevel`), is refused with
`MEMORY_LEVEL_NOT_SUPPORTED_HERE` before anything starts. Use the command-line tool for higher
levels. Containers made with level 0 in the browser and on the command line are identical.

A page cannot measure how much memory the computer has free, so nothing checks in advance that the
browser can give the 2 GiB of level 0. When it cannot, an operation fails with
`MEMORY_ALLOCATION_FAILED` in round 1, when Argon2 first needs the memory, and a session of hidden
wallets fails at its start, when it reserves its work area. The command-line tool checks the free
memory before it asks for any secret.

## What the command-line tool has and the browser does not

The page should say why these are missing where a user would look for them:

- memory levels above 0: a browser cannot give WebAssembly the memory;
- the check of free memory before any secret is asked: a page cannot measure free memory, so the
  2 GiB fails only when it is needed (see [Memory](#memory));
- the private terminal screen, the swap warning and the process protections (no core dumps, locked
  memory that keeps typed and recovered secrets out of swap, no network, no file writes): they need
  the operating system; the page conceals secrets instead, and its workers are terminated after
  each operation;
- the terminal's presentation: the start menu and its entries, the lists of answers, a screen for
  each step with the summary at the end, the numbered frame around a phrase, the help text, the
  colours and the length limit of a typed line: a page has its own layout, forms and help;
- the time estimates of the settings question and of the self-test: their figures were measured
  with the native program; the page shows the measured progress instead;
- the decoy search on every processor core: the package's WebAssembly has no threads for it and
  compares the candidates one after another, so two missing words take longer than on the command
  line;
- a second confirmation of a rekey on the same recovery after `AMBIGUOUS_LENGTH` or
  `LENGTH_DIFFERS`, without its 12 rounds again, offering the owner only the lengths the owner can
  tell apart: the package recovers and confirms in one call, so a page calls `rekey()` again (see
  [Core](#core));
- reading from standard input, exit codes and the long vector replays and benchmarks of
  `test-vectors` and `test-benchmark`: they serve scripts and development, not a page;
- `mhfe serve` and the menu entry that serves a tool: they are the launcher that gives a page its
  fast mode, not something a page runs; the package's launcher is `core/mhfe-fast-mode.py` (see
  [Fast and standard mode](#fast-and-standard-mode));
- the self-test's checks of locked memory, core dumps, isolation and hidden input, the RFC 9106
  Argon2 vector and the check that Argon2 wiped its memory: a page cannot make them, as
  [What a browser cannot check](#what-a-browser-cannot-check) explains.

## What the page should do

The specification and the command-line tool ask applications to do some things the client cannot
do for them:

- show the warning of the command-line tool: "Experimental: not independently reviewed; do not use
  it to protect real funds.";
- link each topic to its README section, as the command-line tool's "More:" lines do (see the table
  below); the page shows the link and loads nothing from it;
- ask for a new password twice (the classes refuse two different entries) and advise a different
  password for each encrypted phrase, used nowhere else; say that another copy of a backup is an
  exact copy of the same words, with the same password and settings;
- say that letter case and the spaces between words count in the password (after the NFKD
  normalization the client applies), and that a fixed form, such as lowercase words with single
  spaces, is the easiest to type again years later;
- where a new container password is set (encrypt, a new wallet, the new password of a rekey), offer
  the user's own password or one that `MhfePasswords.make()` makes, of the kinds the command-line
  tool offers: five dice words, five words and a check word, or sixteen random characters. Show a
  password made once, privately, and have it typed back from the user's copy before it is used,
  showing it again after a wrong copy;
- review a password with `MhfePasswords.review()` before any long work and offer its answers in its
  order (`repairsFirst`), the password as typed always among them; pass the choice as
  `passwordRepair`. Say "If you forgot a word of a password with a check word, type ? in its place"
  only where an existing password is typed, not where a new one is; review a new password and the
  passwords of hidden wallets too, with `passwordRepeat`, and warn when `strength()` calls a
  password weak;
- offer the container length for a 12- to 21-word phrase as a choice the user makes, with 24 words
  selected by default, and show what each gives before the choice (`readPhrase().containers`): 24
  words report a wrong password and hide the phrase's length; the same length keeps the backup's
  length but reports no wrong password (any password gives another valid phrase), shows the length,
  and lets a miscopied word through about once in 16 (12 words) to 128 (21 words). Set `sameLength`
  only on that choice;
- for a same-length container, label every recovered phrase as not verified and offer the check
  against an address or the fingerprint, the only confirmation it has; `{ words }` is refused with
  `NO_BUILT_IN_CHECK` and `{ walletCheck: true }` with `NO_WALLET_CHECK`;
- before an encryption, ask nothing about a BIP39 passphrase, as the command-line tool asks nothing:
  in a tool that encrypts a phrase such a question looks suspicious, and without an answer the
  result's `keep` names any passphrase of the wallet. Pass `walletHasPassphrase` only where the page
  knows the answer, such as for a phrase just drawn with `drawPhrase()`, which has one when a
  passphrase was typed for it, checked or not;
- before a rekey, ask whether the wallet has a BIP39 passphrase, with neither answer preselected, as
  the command-line tool does: once, whatever confirms the recovery, after the kind of confirmation
  is known and before any address or fingerprint is typed, since a reference compared without a
  passphrase matches only the phrase's wallet without one, which says nothing about funds under one.
  Say why it is asked, next to the question: only so that the list of what to keep is complete; MHFE
  stores no passphrase and asks for one only to compare it with an address or a fingerprint. With an
  address or a fingerprint, then ask for the passphrase only when the wallet has one, refuse an
  empty one there, and pass it with the answer;
- wherever a container phrase is typed to be decrypted, checked, rekeyed or opened, read it with
  `MhfeRepair.inspectContainer()` first, as the command-line tool does: for "marked" ask for the
  repair words at once, with a way back to the container phrase; for "notAContainer" say why it is
  not one and offer to type it again or to repair it with its repair words. Repair it with
  `repairContainer()`, show the repaired container phrase with every change, and use it only after
  the user has said so; say that the written container phrase must be corrected too. Without the
  repair words, for "marked" words, offer the search as the command-line tool does: ask first what
  the user knows, an address or fingerprint of the container's own wallet (`searchDecoy()`, seconds
  for one missing word, minutes for two, and no password), one of their wallet, the original seed
  phrase's (`searchWallet()` with `{ address, coin }` or `{ fingerprint }`), the original seed
  phrase's passphrase alone (`{ walletCheck: true }`, its built-in check and the phrase +
  passphrase check of a phrase made by `mhfe new`), or nothing (`{ builtInCheck: true }`, a 12- to
  21-word original seed phrase only). For a wallet, ask then whether a BIP39 passphrase is used
  with the container phrase, or with the original seed phrase, naming whose, and pass it, "" for
  none; the decoy is compared with exactly the passphrase given. Offer only the container's own
  wallet for two missing words, and no own checks for a same-length container. Before
  `searchWallet()` say how long it takes: the candidates (`searchCandidates()`) times one recovery
  in this mode at the settings given (see [Fast and standard mode](#fast-and-standard-mode) for the
  defaults); it looks for one missing word only, and the decoy search for two, an address then
  within `scanGap`, asked as the command-line tool asks it. After a refusal or nothing found, ask
  again what the user knows rather than for the container phrase. Show the words found before the
  container is used;
- show the suite identifier (`suiteId`) when a container is made, and what to keep as the result's
  `keep` list gives it, in its order, adding nothing and leaving nothing out: the container's words
  and the password always; the wallet's BIP39 passphrase, or any passphrase of the wallet where the
  page did not know (`passphraseIfAny`, which the command-line tool words "any BIP39 passphrase of
  the wallet"), the repair words, a PIM or memory level that is not the default and, rarely, the
  word count are added there when needed;
- if it shows the container from `onUnverified`, mark it clearly as not yet verified, and then say
  how the check ended: verified when the promise resolves, wrong and not to be used on
  `VERIFICATION_FAILED`, not verified on a cancel or any other error. Never make repair words from
  that container: the result carries them once the check has passed. A page that does not show the
  container before its check leaves `onUnverified` out and gets only the checked container, as the
  command-line tool writes only the checked one to a file or a program;
- show the words it has read back to the user in full: `readContainer()` and `readPhrase()` return
  them;
- before encrypting, also a new phrase, look at `otherLengths` of the container chosen from
  `readPhrase().containers`: when it is not empty (about one phrase in four billion, and never for
  a same-length container), tell the user to note the word count and choose it during recovery,
  because automatic detection would not give the phrase on its own. After an
  encryption or a rekey, the result's `otherLengths` says the same, and `keep` then lists the word
  count;
- show master key fingerprints openly, with what they are of: `containerFingerprint` is of the
  container's own words, not the wallet; `fingerprintWithoutPassphrase` is of a wallet without a
  BIP39 passphrase; `fingerprintWithPassphrase` is with the passphrase given. They do not reveal the
  phrase. Show a hidden wallet's fingerprint only together with its phrase;
- before a recovery, say that the seed phrase will be shown, so recover only on a trusted offline
  computer. Show what each candidate's `status` means: "verified" confirms the password, not the
  wallet, which the check confirms; "noBuiltInCheck" is not verified, so confirm it against the
  wallet; "readAs24" is not verified, and for a shorter original seed phrase the password or a
  setting is wrong; "readAs24Chosen" is not verified, so compare it with the wallet. For
  "ambiguous", ask the user to compare each candidate with the wallet. Every 24-word reading gets
  the 16-bit source check (`walletCheck`) with the `passphrase` given to `decrypt()`, "" for none:
  the container does not show whether the phrase was made with the check. When a 24-word reading
  comes out, ask whether a BIP39 passphrase is used with the phrase, and say why in a few
  sentences, not only a link; ask before the recovery or decrypt again with the answer. Say
  "passes the 16-bit check" for `true`; for `false` say that it matters only if the wallet was made
  with the check, as a phrase made without it fails. When the user is done,
  remove the phrase from the screen, say so, and ask the user to close the page;
- offer a check only where `readContainer()` says it applies, and show what an address check will
  search (`MhfeWallet.describeAddress()`) before it runs. Beside a match, list each of the original
  seed phrase's own checks that `evidence` shows passing, as the command-line tool does, and when
  `{ words }` matched at another length, say that the check found `evidence.builtInCheck` words;
- before a rekey, tell every user, whatever the container, in one plain sentence: wallets that
  other passwords open on the old container do not move to the new one, so keep the old container,
  its passwords, and a PIM or memory level that is not 0, until you have moved their funds. Your
  own wallet's addresses do not change. Ask nothing about such wallets, as an answer
  would be a record of one. Show the phrase of an owner confirmation concealed, ask the owner to
  compare it with a written record, not with memory, and remove it after the answer. Say afterwards
  that the old container phrase and password still open the wallet, and that the new container
  phrase is rehearsed with a check;
- before hidden wallets, say every time that nothing is created or stored and that the container and
  each password give the same wallet every time; ask for the main wallet's BIP39 passphrase every
  time; show no list or count of the wallets opened, as the command-line tool shows them only on its
  private screen. Under each wallet, say that there is no need to write it down: the container and
  this password give it again. When the user is done, say to fund hidden wallets only from sources
  not linked to the user, and that a rekey of the container changes them. Close the session when the
  user leaves the page and after a while without use, since it holds the Argon2 work area and the
  passwords used until then;
- offer the wallet check of a new phrase only with a BIP39 passphrase and with neither answer
  preselected, and say what it costs: about 65,536 draws, and 16 of the phrase's 256 bits. When the
  user chooses it, warn that all funds belong under this passphrase, since the wallet without it
  stays empty, and warn when `strength()` calls the passphrase weak, since the check is only as
  strong as the passphrase;
- check every class the page uses when the page opens, before any of its fields is enabled:
  `startupCheck()` of each class, that of `MhfeClient` with `{ argon2: false }` unless the page
  wants Argon2's known answer at once. Keep a class's controls closed while its check runs, and
  closed for good when the report's `passed` is false;
- when a check fails, show the failed parts with their labels and details, or the message of the
  `SELF_CHECK_FAILED` error, which names the part, and say what the command-line tool says: do not
  use this program on this computer. Advise trying another computer or browser and a copy of the
  package checked against its release's `SHA256SUMS`, and link to the README section on a failed
  self-test. Show `SELF_CHECK_FAILED` from a later call, such as an Argon2 operation, in the same
  way;
- on `PACKAGE_MISMATCH`, say that the page's files of the package come from different builds and
  offer nothing of that class; on `WORKER_FAILED`, show the message and let the user try again;
- offer the full self-test as an action of its own: `fullCheck()` of every class the page uses, one
  after another, each part shown as `onProgress` reports it, with its label and outcome. Show a
  warning with its detail and a part not available or not run with its reason, such as "not
  available in a browser: a web page cannot keep its memory out of swap"; neither is a failure;
- offer the published vectors as another action, `selfTest()`, and show its result for each vector:
  suite 3 encrypts as published or not, suite 4 recovers as published or not. When `passed` is
  false, say that this program does not compute MHFE as published, must not be used for a real
  phrase, and that another computer or build should be tried, and say where it went wrong with
  `fault.message`, the sentence the command-line tool shows, rather than composing one from
  `firstWrongRound`, which does not tell a fault before Argon2id from one in it;
- keep `check()` apart from the self-test: it rehearses the recovery of the user's container and
  checks nothing of the program. A self-test calls `startupCheck()`, `fullCheck()` and `selfTest()`
  only;
- warn in standard mode that the operation takes longer, because the four Argon2 lanes then run one
  after another;
- ask the user to rehearse the recovery with the container typed from the finished backup, not from
  the screen: the check at creation covers the words the page produced, not the copy, and a wrongly
  copied word still passes the BIP39 checksum in about one case in 256, and in a same-length
  container as often as one case in 16; make repair words only from a container whose recovery was
  rehearsed;
- start an operation only on an explicit user action and offer a cancel button; start `selfTest()`
  only when the user asks for it, since it takes minutes. The checks before first use need no
  action.

The README sections that the command-line tool links to:

| Topic                                               | README section                                                                                    |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| A trusted offline computer, and swap                | [Getting started](https://github.com/hobby-eng/mhfe#getting-started)                              |
| PIM and memory level                                | [Settings: PIM and memory level](https://github.com/hobby-eng/mhfe#settings-pim-and-memory-level) |
| A 24-word container or one as long as the phrase    | [24 words or the same length](https://github.com/hobby-eng/mhfe#24-words-or-the-same-length)      |
| Making a password                                   | [`mhfe password`](https://github.com/hobby-eng/mhfe#mhfe-password)                                |
| A password with a check word                        | [A check word](https://github.com/hobby-eng/mhfe#a-check-word)                                    |
| What to keep after an encryption, and the rehearsal | [`mhfe encrypt`](https://github.com/hobby-eng/mhfe#mhfe-encrypt)                                  |
| What a check can and cannot tell                    | [`mhfe check`](https://github.com/hobby-eng/mhfe#mhfe-check)                                      |
| A recovered phrase that is not verified             | [`mhfe decrypt`](https://github.com/hobby-eng/mhfe#mhfe-decrypt)                                  |
| A new password or new settings                      | [`mhfe rekey`](https://github.com/hobby-eng/mhfe#mhfe-rekey)                                      |
| A new phrase and its wallet check                   | [`mhfe new`](https://github.com/hobby-eng/mhfe#mhfe-new)                                          |
| Hidden wallets                                      | [`mhfe wallets`](https://github.com/hobby-eng/mhfe#mhfe-wallets)                                  |
| A failed self-test                                  | [`mhfe self-test`](https://github.com/hobby-eng/mhfe#mhfe-self-test)                              |
| Repair words                                        | [`mhfe repair`](https://github.com/hobby-eng/mhfe#mhfe-repair)                                    |

## What the browser cannot wipe

A password, a BIP39 passphrase, a phrase and dice rolls given to a class are copied into UTF-8
bytes once its check at start has passed, transferred to the worker, so that no copy stays with the
class, and wiped there; a `Uint8Array` the page passes is always copied into an array of its own,
never transferred or emptied, whatever its kind. Text with an unpaired surrogate, a phrase included,
is refused with `INVALID_PASSWORD_TEXT` rather than changed by the browser. The Rust code and the
Argon2 bridge overwrite every copy of these bytes, the keys and the states they hold, and every
worker is terminated when its operation or session ends. A cancelled operation, or a session of
hidden wallets closed while it opens a wallet, terminates its worker instead, as soon as the worker
has loaded the WebAssembly if it is still loading it: the browser frees that memory without
overwriting it. What reaches the page
is a JavaScript string, which the browser cannot erase: a password typed into a page, a recovered or
new phrase, a generated password, the words of a check word review, the phrase of an owner
confirmation and the phrases of hidden wallets. Pass passwords and passphrases as `Uint8Array` where
possible, keep phrases and passwords on screen only as long as needed, and close the tab afterwards.
