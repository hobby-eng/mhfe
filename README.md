# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics

[![CI](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml)
[![Release](https://github.com/hobby-eng/mhfe/actions/workflows/release.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/release.yml)
[![Test vectors](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml)
[![RustSec audit](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml)
[![Build provenance: GitHub attestations](https://img.shields.io/badge/build%20provenance-GitHub%20attestations-2ea44f)](https://github.com/hobby-eng/mhfe/attestations)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

<p align="center">
  <img src="assets/mhfe-mascot.png" alt="MHFE penguin mascot carrying a cold-storage metal backup" width="240">
</p>

<p align="center"><sub>The penguin lives in the cold, like the backups MHFE is made for. It holds a
steel backup with 24 words and waddles from side to side, much as a Feistel network swaps its two
halves in every round.</sub></p>

MHFE turns a Bitcoin or other BIP39 seed phrase (12, 15, 18, 21 or 24 English words) into a
password-protected **container of 24 words**, or, for a phrase of 12 to 21 words, a container
**of the same length**. The container is a valid BIP39 phrase that fits the same metal backup or
capsule. Recovery returns the exact original phrase; your wallet, addresses and BIP39 passphrase
stay as they are.

At the default settings a recovery takes about one to two minutes and 2 GiB of memory. An
encryption takes twice as long because MHFE recovers the new container to check it. See
[settings](#settings-pim-and-memory-level) for other memory levels and time costs.

This repository provides the command-line tool, Rust library and browser package. The companion
[specification](https://github.com/hobby-eng/mhfe-spec) defines suite
`MHFE-BIP39-256-EXPERIMENTAL-3` for 24-word containers and suite
`MHFE-BIP39-LP-EXPERIMENTAL-4` for same-length containers.

> **Experimental.** MHFE has not been reviewed by independent cryptographers. Do not use it to
> protect real funds. Keep the backup of your original seed phrase until you have rehearsed a
> recovery.

## How it works

MHFE is made for **cold storage**: a backup written once on paper or metal and recovered perhaps
years later on an offline computer. It protects the stored phrase, not the wallet's signatures or
address hashes; a break in those algorithms, including a quantum attack, can still put funds at risk.

The phrase's entropy passes through twelve Feistel rounds. Each round derives its key from the
password through Argon2id and depends on the previous round, so a password guess requires a full
recovery. The result is encoded with an ordinary BIP39 checksum. No salt, version or settings are
stored alongside it; retain the [settings](#settings-pim-and-memory-level) if you change them.

### 24 words or the same length

A 24-word container is the default. For a shorter original phrase, encryption also offers a
same-length container; `?` compares them and `--same-length` selects the latter.

| Original phrase | Container            | Recovery check                                                                                   | A miscopied word passes the BIP39 checksum    |
| --------------- | -------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------- |
| 12 to 21 words  | 24 words, suite 3    | A built-in hash check usually detects a wrong password or settings and finds the original length | About once in 256                             |
| 24 words        | 24 words, suite 3    | Every password gives a valid phrase; compare with your wallet                                    | About once in 256                             |
| 12 to 21 words  | Same length, suite 4 | Every password gives a valid phrase; compare with your wallet                                    | About once in 16 (12 words) to 128 (21 words) |

Short originals leave room for the built-in check in suite 3's 256-bit state. Same-length containers
have no such room and reveal the original length. The check tests the password and settings, not
wallet identity or a BIP39 passphrase, and an attacker can use it to recognise a guess too.
[`mhfe check`](#mhfe-check) compares a recovery with a wallet address or fingerprint. The optional
[phrase + passphrase check](#mhfe-new) for new wallets is a separate, 16-bit check.

Without a built-in check, the container alone cannot distinguish passwords. A wallet's public
history can: if the original phrase's wallet without a BIP39 passphrase has received funds, an
attacker can recognise it on the blockchain. Keeping that wallet unused and using an independent
passphrase for the funded wallet requires guessing both secrets together. The
[specification](https://github.com/hobby-eng/mhfe-spec) analyses these limits; its attack-cost
estimates are for suite 3, while its deniability discussion also covers suite 4.

**Plausible deniability.** For a 24-word original, another random password produces a valid decoy
phrase that MHFE also labels as not verified. Its wallet needs believable funds and history. This
argument has not been independently reviewed, does not cover an attacker who knows that the original
is shorter, and depends on every backup being an exact copy of the same container. Another record,
such as the original paper backup or a hardware wallet, can contradict the disclosure. See
[Ways to use it](#ways-to-use-it) for the wallet arrangements and [Chosen words](#chosen-words) for
another way a decoy can be recognised.

## Ways to use it

> [!WARNING]
> **The MHFE password is not your BIP39 passphrase!** The password opens the container; a BIP39
> passphrase, sometimes called the 25th word, belongs to the wallet and stays the same after MHFE.
> Every MHFE password and every wallet or decoy passphrase must be independent: never reuse one
> or derive one from another.

The optional branches below all use the same container. The final branch recovers your original
wallet:

```text
24-word container phrase
│
├── typed into a wallet as it is
│   ├── without a BIP39 passphrase ........... decoy wallet, a small amount or nothing
│   └── with a decoy BIP39 passphrase ........ prepared decoy wallet with believable funds
│
├── recovered by MHFE with another password    (a 2nd, 3rd, 4th ..., each optional)
│   └── another valid 24-word phrase for each password
│       ├── without a BIP39 passphrase ....... a decoy to hand over, or a hidden wallet
│       └── with its own BIP39 passphrase .... a hidden wallet behind a passphrase too
│
└── recovered by MHFE with your password
    └── your original seed phrase
        ├── without a BIP39 passphrase ....... your wallet
        └── with its own BIP39 passphrase .... your wallet: the strongest arrangement
```

**The container's own wallet** can be empty or hold a small decoy amount, with an optional decoy
BIP39 passphrase. Whoever receives the words and the needed passphrase can spend that amount.
This convinces only someone who does not know that MHFE was used. Enter the container only into a
wallet you trust: a copy also lets its holder try MHFE passwords offline.

**Other MHFE passwords** can produce a decoy to disclose, subject to the
[deniability limits](#how-it-works), or hidden wallets behind the wallet you disclose honestly.
[`mhfe wallets`](#mhfe-wallets) explains how to open and protect them. Nothing records the
passwords or how many wallets you use; each depends on the exact container and settings, and
[rekeying](#mhfe-rekey) does not transfer it.

**Your original wallet** opens as before. The strongest arrangement described here is a random
24-word original with an independent BIP39 passphrase, while its wallet without that passphrase
stays unused. Each additional secret must be backed up: losing the passphrase loses its wallet,
just as losing the MHFE password loses the recovery.

## Getting started

Download and [verify](#release-files) the archive for your system from the
[releases page](https://github.com/hobby-eng/mhfe/releases), unpack it and run `mhfe` in a terminal.
Nothing is installed. With no command, by a double-click or with `mhfe-launch`, it opens the start
menu. Choose with the arrow keys and Enter or an answer's number; Escape cancels.

Use a trusted computer that stays offline while it holds secrets, preferably a Linux live system
started from a USB stick with the network off. On Linux, MHFE applies kernel restrictions against
new sockets and file writes and reports which protections hold. A directly started command also
uses its own network namespace where permitted. Already open descriptors, including sockets and
redirected output, remain usable, so the protections cannot replace an offline environment. On
Windows, Windows PE is preferable to an everyday system, but MHFE has not been tested there yet.

Use encrypted swap or none. The operating system can otherwise write Argon2's work area to disk,
leaving material that makes password guesses cheaper; it can remain there for years. MHFE warns
about unencrypted swap on Linux and reports whether secrets could be locked out of swap. A live
system usually has none; macOS encrypts swap, and Windows needs BitLocker or no page file. The
[security notes](https://github.com/hobby-eng/mhfe/blob/main/SECURITY.md#secrets) explain the
protections and their limits.

Every secret-handling command runs [startup checks](#mhfe-self-test) before asking for a secret.

## Commands

`mhfe <command> --help` lists the options. Keep a compatible program offline with the backup.
The grey "More:" links lead to the sections below.

At a terminal, typed and displayed secrets use private screens cleared when the step ends, keeping
them out of ordinary scrollback; terminal logging or screen recording can still retain them.
Enter or Escape clears a displayed result after you have copied it. The final summary contains no
secret words. Commands that require such a screen say so below; [For scripts](#for-scripts)
describes redirected input and output.

A grey word-list hint counts matches after one letter, lists them from two and reports no match.
Tab completes the common prefix; Ctrl+W deletes the last word. Password hints use the EFF list,
where Tab remains part of the password. Hints appear only where the input is already visible.
Seed, container and repair words accept four-letter prefixes and any letter case; passwords have
their own [exact-text rules](#mhfe-password).

A shown seed phrase, a newly made container or a container repaired by `mhfe repair` has an
eight-hex-digit master key fingerprint below it. It identifies the wallet with the passphrase
in `mhfe new`, and otherwise the wallet without one. Under a container it identifies the
container's own wallet, not your original wallet. For a wallet with a passphrase, compare its
fingerprint through [`mhfe check`](#mhfe-check). This line is absent from script output and
container phrases repaired or found inside another command.

### `mhfe password`

Make random words from the [EFF dice list](https://www.eff.org/dice) of 7,776 words: use four,
better five. `--dice` uses real dice, `--words N` sets the count, and `--chars N` makes random
characters instead (16 by default, about 93.3 bits) from 57 letters and digits without look-alikes.
The system's cryptographic random generator draws every word or character equally likely.

A password accepts one line, up to 1,024 bytes after Unicode normalization. Letter case and spaces
count; control characters, line and paragraph separators and characters unassigned in Unicode
17.0.0 are refused. Lowercase words with single spaces are easiest to reproduce. Keep the password
apart from the container: it is shown once and not stored.

`mhfe encrypt` warns below an estimated 50 bits. Its offline estimator recognises the EFF and BIP39
lists, common passwords, years, repetitions, sequences, keyboard rows and substitutions, but may
overrate unfamiliar words or names. Generated passwords have a known strength.

The menu offers five words, five words with a check word, or sixteen characters; Enter generates
another and Escape leaves. `encrypt`, `new` and `rekey` offer these same choices before setting a
password. A generated password must be typed back from your written copy; a mismatch shows it again.
`--new-password own|words|check-word|chars` selects the choice; scripts always supply their own.

#### A check word

`mhfe password --check-word` adds a sixth word computed from five random words, as
[MHFE-PASSWORD-CHECK-1](https://github.com/hobby-eng/mhfe-spec#optional-password-check-word-mhfe-password-check-1)
defines. Before the long wait, MHFE offers:

- a matching check word: a confirmation in the summary;
- one `?` or misspelt word: its repair, shown for approval; a word left out entirely cannot be
  distinguished from an ordinary five-word password;
- six valid words that do not fit: six possible repairs, one per position, to compare with your copy.

It also offers lowercase, single-space text when only that form fits. Corrections require your
approval, and the typed password remains a choice: nothing in the container records this profile.
A matching check word confirms only that the words fit together, not that they open the container.

The check word adds no strength: five random words retain 64.6 bits. Keep it secret too; disclosure
of that word alone leaves about 51.7 bits to guess. If you might disclose another password of the
same container, make both in the same style, with a check word, so their forms do not distinguish them.

### `mhfe encrypt`

Enter the original phrase and confirm the password twice. For 12 to 21 words, choose the
[container length](#24-words-or-the-same-length); `--same-length` selects it without asking, and
`--same-length no` keeps 24 words without asking.
The result names the suite. Copy the container while MHFE recovers it for comparison, and rely
on it only after "Verified"; then clear the private screen.

The summary lists what to keep: the container, password, any wallet BIP39 passphrase, and, where needed,
repair words, changed settings or the original word count. Keep the repair words and a note of the
word count apart from the container: the note tells which length the container hides. MHFE
encrypts only the phrase: it does not ask for its wallet passphrase, but always reminds you to keep
one if used.

Before relying on the backup, run [`mhfe check`](#mhfe-check) with the words from your written
copy, not the screen, and retain the original backup until it matches. Copy additional containers
exactly. The same phrase, password and settings always reproduce the same container, so use a
separate password for each phrase.

### `mhfe check`

Rehearse recovery without showing the original phrase. The result is "matches", "does not match" or
"not verified"; a matched address also shows its path, such as `m/84'/0'/0'/0/5`. "Not verified"
means that nothing tells a right password from a wrong one: a 24-word reading without an address or
fingerprint, or several lengths that pass their built-in checks by chance, which MHFE lists. The terminal summary names every
check the recovery passed, including a missing-word search's container-wallet reference when used.
Enter the container from your written copy.

A receiving address compares the intended wallet, including its BIP39 passphrase; a master key
fingerprint is quicker but only 32 bits. Do not keep either reference beside the container. MHFE
asks for the coin, or takes `--coin`, and searches the first 100 receiving and change addresses of
accounts 0 to 9 on its standard paths, or the one specified by `--path`.

Supported addresses are Bitcoin, Ethereum and all EVM networks (including BNB Smart Chain, Polygon,
Avalanche C-Chain, Arbitrum, Optimism and Base), XRP, Tron, transparent Zcash, Dogecoin, Bitcoin Cash,
Litecoin, Ethereum Classic, Cosmos, Injective and Dash. Dash includes Core `X…` and Platform
`dash1k…` (DIP17, `m/9'/5'/17'/account'/0'-1'/index`). Shielded Zcash (`zs1…`, `u1…`) and Dash
Orchard (`dash1z…`) are unsupported: use the same wallet's transparent address.

Other references in the menu are the [built-in check](#24-words-or-the-same-length) for a short
original in a 24-word container, and the [phrase + passphrase check](#mhfe-new) for a new 24-word
phrase drawn with it. The latter checks only the 24-word reading, requires a nonempty passphrase
and does not identify the wallet.

For the built-in check, "Detect automatically" (`--words auto`) finds a passing short length and
asks whether the original wallet has a passphrase (`--passphrase-used yes|no` answers beforehand),
so that a pass of the optional check of a 24-word reading is reported; it does not verify the
reading. If no single length is found, MHFE asks for
it: a stated short length that does not pass does not match, and for 24 words an address or
fingerprint confirms the same recovery without repeating the rounds. A detected short length takes
precedence over a stated one, and the summary reports it.

A mismatch cannot identify which input is wrong: the password, settings, container, passphrase or
reference. Script input and its default coin are in [For scripts](#for-scripts).

### `mhfe decrypt`

Recover the original phrase and show it on the private screen. The summary names the container's
format; its [length and checks](#24-words-or-the-same-length) determine what can be verified.
An unchecked result, including a wrong-password result, can be another valid wallet.

Every 24-word reading is tested against the optional [phrase + passphrase check](#mhfe-new),
because the container does not record whether it was used. MHFE asks whether that wallet has a
BIP39 passphrase and tests with it or with none; `--passphrase-used yes|no` answers beforehand.
A pass is statistical evidence, not wallet identification. Failure matters only if the original
was drawn with the check. The [script input order](#for-scripts) specifies when to provide it.

`--words N` states the original length and accepts only a 24-word container or a same-length one
of N words. It does not override a passing built-in check at another length. With 24 stated and a
shorter length detected, both readings are shown, shorter first; compare with your wallet. With a
short length stated and no passing check, the password or settings may be wrong, or the original
may have 24 words. About one container in four billion passes several short-length checks by
chance; MHFE shows each reading for comparison, or you select one with `--words N`.

### `mhfe rekey`

Recover the old container once and put the same original phrase into a new container, with a new
password, new settings or both, in the old container's format. Before the old words are entered,
MHFE warns every user that wallets opened by other passwords do not move to the new container;
it asks nothing about their existence.

Recovery must be confirmed before the phrase is encrypted again:

- A stated short length whose single built-in check passes confirms that recovery.
- A different detected length needs a wallet address, fingerprint or comparison with the shown
  phrase. If 24 words were stated but a short check passes, only an address or fingerprint,
  compared with both readings, resolves it.
- A 24-word original, a same-length container or "Detect automatically" (`--words auto`) needs an
  address, fingerprint or word-for-word comparison with an independent backup. A detected check
  alone is insufficient: a 24-word original can pass a short check by chance.
- Several passing short lengths cannot be resolved by the built-in check, even with a stated
  length. Use an address or fingerprint, or choose a reading and compare its words with your backup.

The shown-phrase comparison waits for an explicit answer entered after the question; memory alone
is a weak reference. It is unavailable without a private screen. The 16-bit phrase + passphrase
check is reported when it passes, but never suffices to confirm a rekey. Re-encrypting under the old
password would prove nothing either. Another confirmation attempt reuses the recovered state.

`--confirm check|address|fingerprint|show` selects confirmation. MHFE asks explicitly, with no
default, whether the wallet has a BIP39 passphrase, so the retention list includes it;
`--passphrase-used yes|no` answers beforehand. For an address or fingerprint, it asks for the
passphrase only when you said there is one and refuses an empty answer. Those reference inputs are
collected before recovery. After owner-only confirmation of an unchecked phrase, MHFE asks for its
wallet passphrase if used and gives the fingerprint for rehearsing the new container with
`mhfe check --fingerprint`.

New settings and a [new password](#mhfe-password) then produce a container as in
[`mhfe encrypt`](#mhfe-encrypt). Rehearse its written copy, preferably on another day. **The old
container remains valid with the old password.** Keep it, its passwords and changed settings until
all decoy or hidden-wallet funds have been moved. Your original wallet keeps its addresses; those
other wallets change with the container. Keeping both backups also leaves two different containers
of the same phrase, which the deniability analysis does not cover.

### `mhfe new`

Generate a random 24-word wallet and its container together. MHFE draws the phrase from the
operating system's random generator, shows it once for your wallet and encrypts it as in
[`mhfe encrypt`](#mhfe-encrypt). Without a private screen it refuses to start.

If the wallet has a BIP39 passphrase, MHFE asks whether to add a **phrase + passphrase check**, with
no choice preselected. Without a passphrase there is no such check. The optional
[MHFE-WALLET-CHECK-SEED-1 source profile](https://github.com/hobby-eng/mhfe-spec#optional-source-profile-a-recovery-check-for-new-24-word-phrases)
draws a phrase whose tagged BIP39-seed hash starts with 16 zero bits. It is experimental and applies
to new wallets only; the exact bytes are in
[the API guide](https://github.com/hobby-eng/mhfe/blob/main/docs/API.md).

A wrong password or passphrase passes about once in 65,536, so this is statistical evidence and
cannot identify the wallet. A password guess must also supply the passphrase. Drawing the phrase
this way leaves about 240 of its 256 bits, with these costs:

- Keep funds only under that passphrase; never use the phrase's wallet without one. Its public
  history would allow separate password guesses. The check is only as strong as the passphrase,
  and MHFE warns about a weak one.
- The passphrase is fixed for the check. Finding another that passes takes about 65,536 tries;
  finding a passing decoy MHFE password takes about 65,536 recoveries.
- A passing phrase is distinguishable statistically from a random one. The specification's
  deniability analysis assumes uniformly random originals and does not cover this profile by itself.

Without the check, use the [normal wallet comparison](#mhfe-check). Keep a compatible program with
the backup in either case.

#### Chosen words

`mhfe new` can choose one word at a position from 1 to 24 or anywhere, and one word the phrase must
never hold (`--never-use`); `--choose-word no` draws every word at random without asking, and
`--wallet-check yes|no` answers the question about the check. The chosen word is entered and shown
only on private screens; the summary records only whether there was one. MHFE draws until both
wishes hold, uniformly among phrases that meet them, rather than among all phrases. This is an
application feature, outside the specification's uniform-source assumptions.

Before drawing, MHFE reports the remaining entropy for someone who knows the wishes:

- A fixed-position word costs 11 bits, one anywhere about 6.4 bits, and an excluded word about 0.02.
- The source check alone leaves about 240 bits. A fixed word, an excluded word and that check leave
  at least 228.98 bits; without the check the minimum is 244.98.
- Less than 240 bits is allowed but not recommended.

**We advise against choosing a word.** Its larger practical cost is recognising password guesses
and decoys. If an attacker knows that "zoo" is first, only about one in 2,048 wrong-password phrases
passes that filter; a decoy almost always fails it. A word anywhere passes about once in 85. This
also reduces the benefit of jointly guessing the BIP39 passphrase, even though each password guess
still requires recovery. A personal word can be guessed or learned: keep it secret and choose no
word for a wallet protected by a decoy. An excluded word alone reveals much less.

A known chosen word in a shorter original already protected by a built-in check costs randomness;
in a same-length container it also acts as a password filter. Conversely, a personally meaningful
word in the main wallet you would disclose honestly may make that wallet look plausible; hidden
wallets behind it still have random phrases. Public wallet history remains the main evidence.

### `mhfe wallets`

Open the valid 24-word wallet produced by each other password of a 24-word container, for a decoy
or a [hidden wallet behind an honest disclosure](#ways-to-use-it). Nothing is created or stored:
the same container, settings and password always give the same wallet.

Run [`mhfe self-test --vectors`](#mhfe-self-test) on the computer before funding a hidden wallet.
All wallets and their passwords share a private screen cleared at the end; no summary records the
wallets or their count, and the command requires that screen. A password whose reading passes a
short original's built-in check is refused, as is one passing the optional source check with the
main wallet's passphrase or with none, so a hidden wallet cannot be labelled verified.

Keep each password strong and independent. Avoid transaction links to you or the main wallet;
a watch-only copy on an everyday device is also evidence. A hidden wallet depends on the exact
container, suite and settings: move its funds before [rekeying](#mhfe-rekey), and retain those
inputs and its password. Hidden wallets currently have 24 words only.

### `mhfe repair`

Repair words are extra words on a card kept apart from the container. They repair unreadable or
wrong words without its password or Argon2. `encrypt`, `new` and `rekey` offer them, four
recommended; `--repair-words N` selects 0 for none or one of these counts:

| Repair words | Unreadable words repaired | Or wrong words repaired |
| ------------ | ------------------------- | ----------------------- |
| 2            | 2                         | 1                       |
| 4            | 4                         | 2                       |
| 6            | 6                         | 3                       |
| 8            | 8                         | 4                       |

After verification, copy the card labelled MHFE-REPAIR-1, with its numbered words; the summary
includes it in what to keep. A new container needs a new card. `mhfe repair-words` makes one for an
existing container, and the start menu has one entry for both commands.

In `mhfe repair`, enter `?` for unreadable container or card words. Words outside the BIP39 list
also count as unreadable; the card accepts its label and numbers. Each repair is shown for explicit
acceptance, including what was read there. Correct the written copy and rehearse with
[`mhfe check`](#mhfe-check). Detected decoding failures and invalid BIP39 checksums are rejected,
but a wrong card or damage beyond the repair bound can yield a checksum-valid wrong result.
**Successful repair does not confirm your wallet.**

`decrypt`, `check`, `rekey` and `wallets` accept `?` and ask for the card themselves. Invalid container
input offers retyping or repair. The repaired words are used only after "Use it"; the summary names
positions, never their contents. `--repair` asks for the card immediately after the container,
at a terminal or in a script. Without a card, Enter offers a
[missing-word search](#can-mhfe-find-a-missing-word-without-the-repair-words) when `?` marks the
missing words, or a return to retyping. `mhfe repair` offers that search too; its settings are then
asked, or supplied by `--pim`, `--mem` and `--scan-gap`.

Keep the card apart to avoid losing both in one accident, and protect it like a partial container.
It can restore a damaged copy and alone narrows the possible containers: eight repair words leave
roughly `2^168` checksum-valid 24-word containers, but `2^40` for 12 words, in the idealized checksum
model. They do not identify the right container or bypass the password. The
[MHFE-REPAIR-1 specification](https://github.com/hobby-eng/mhfe-spec#optional-repair-words-mhfe-repair-1)
and [repair implementation](https://github.com/hobby-eng/mhfe/blob/main/src/repair.rs) define the bytes.

### `mhfe self-test`

**At startup**, every secret-handling command and the start menu compare their parts with known
answers before accepting secrets. The checks exercise refusals as well as valid cases, replay ten
published round vectors with recorded keys instead of full-size Argon2, and read back core-dump,
isolation and memory-locking protections. They take a few hundredths of a second and are silent
when they pass. The [check catalogue](https://github.com/hobby-eng/mhfe/blob/main/docs/API.md#self-checks)
describes each part and the independent origin of its answers.

A failed check stops before the first question with exit code 1 and a diagnostic linked here.
Failure to disable core dumps also stops the command, since a crash could write secrets to disk.
Check the download, try another computer and report the failure. Startup checks cover only what
they exercise, so still [verify downloads](#release-files).

**`mhfe self-test`** runs the startup checks and slower cases in a few seconds, using about 256 MiB:
Argon2 at 64 and 256 MiB, all 27 published round vectors, additional format, word-list, repair and
wallet cases, every Unicode character against the password rule and normalization, 1,024 bytes
from the random generator and the terminal's ability to disable echo. A secret prompt itself
refuses to read if echo stays on.

Each part reports its result. "Not available here" with a reason is not a failed known answer;
a yellow "!" warns about a weaker protection. The final result is success with exit code 0, or a
failed check with exit code 1. The start menu offers this test and the full-size variant below.

**`mhfe self-test --vectors`** also encrypts suite 3's public zero-12 vector and recovers suite 4's
same-length-zero-12 vector at their specified cost, 2 GiB and twelve rounds each, in about two to
four minutes. It compares against the published results and identifies the first divergence,
including whether an Argon2 input or output differed. This can find full-size faults that reduced
checks miss; an encrypt/decrypt round trip could reproduce the same fault both ways. Run it once
before relying on a computer for recovery or a hidden wallet.

`mhfe serve` checks only hashes before verifying a page. `test-vectors`, `test-benchmark`, help and
version requests handle no secrets and have no startup check. No test proves that a random generator
is unpredictable: these tests detect stuck or plainly broken output. Browser checks and their
platform limits are in the
[browser guide](https://github.com/hobby-eng/mhfe/blob/main/docs/BROWSER-PACKAGE.md#self-checks).

## Settings: PIM and memory level

Both default to 0; most people should leave them there. Each command offers the defaults or custom
values, and `--pim` and `--mem` supply them beforehand. Raising them also increases your recovery cost:

| Memory level (`--mem`) | 0     | 1     | 2     | 3     | 4     | 5      | 6      | ... 21 |
| ---------------------- | ----- | ----- | ----- | ----- | ----- | ------ | ------ | ------ |
| Memory needed          | 2 GiB | 3 GiB | 4 GiB | 6 GiB | 8 GiB | 12 GiB | 16 GiB | 3 TiB  |
| Recovery at PIM 0, min | 1–2   | 1.5–3 | 2–4   | 3–6   | 4–8   | 6–12   | 8–16   | ...    |

Encryption takes twice those times. PIM (0 to 1023) multiplies time: 1 doubles it, and 1023 takes
roughly 17 to 34 hours per recovery. The 64-bit CLI supports every memory level and checks available
memory before secrets are entered, including Linux container or systemd limits. Browser limits are
[below](#in-the-browser). A higher setting adds a fixed factor; another random password word
multiplies a guesser's work by 7,776.

> [!WARNING]
> **Retain any nondefault settings.** The container does not record them. Recovery needs exactly
> the same values; otherwise recovery may fail its checks or yield a different valid phrase.
> Forgotten values require full recoveries across PIM 0 to 1023 or memory levels 0 to 21, and an
> unchecked result also needs wallet comparison.

## In the browser

The browser package offers the same wallet operations through four independent modules: core,
repair words, passwords and wallet tools. It loads no remote resources and supports memory level 0
only. See the [module guide](https://github.com/hobby-eng/mhfe/blob/main/docs/BROWSER-PACKAGE.md#modules)
and [platform limits](https://github.com/hobby-eng/mhfe/blob/main/docs/BROWSER-PACKAGE.md#what-the-command-line-tool-has-and-the-browser-does-not).

Standard mode works even from a local file. For parallel Argon2, `mhfe serve tool.html` serves the
page on 127.0.0.1 with the required headers and opens it; secrets stay in the page. A tool and its
matching `mhfe-fast-mode.sha256` beside the program also appear as the menu's first entry.
The package's `core/mhfe-fast-mode.py` launcher works with Python 3.8 or later without MHFE.
Both launchers require a matching checksum file. Mode setup and measured times are in
[Fast and standard mode](https://github.com/hobby-eng/mhfe/blob/main/docs/BROWSER-PACKAGE.md#fast-and-standard-mode),
and integration and startup/full checks are documented in that guide.

## For scripts

`--stdin` reads the answers from standard input, one per line, instead of asking:

- `encrypt`: the phrase, the password, and the password again; the container has 24 words unless
  `--same-length` is given, and with `--repair-words N` its repair words follow it on a second line
  of the output. As at a terminal, the list of what to keep names any BIP39 passphrase of the
  wallet;
- `decrypt`: the container and the password, and with `--passphrase-used yes` the BIP39
  passphrase of the original seed phrase on the next line, for the 16-bit check, read only when a
  24-word reading comes out; with `--repair`, the repair words follow the container on their own
  line, `?` marking unreadable words in either, and the repair is told on standard error. `check`
  takes `--repair` the same way;
- `check`: the container and the password, then with `--address` or `--fingerprint` the reference
  and the BIP39 passphrase (an empty line if the wallet has none); with `--words N` nothing more,
  and with `--words auto` the BIP39 passphrase of the original seed phrase (an empty line if none).
  `check --stdin` needs one of these three options, because it cannot ask which reference to use.
  Nor can it ask for the coin: `--address` without `--coin` means a Bitcoin address, as in earlier
  versions. The summary then says "Bitcoin, as no --coin was given", and an address that is not
  Bitcoin's is refused with a message that names Bitcoin and `--coin`; give `--coin`, such as
  `--coin ethereum`, for an address of another coin;
- `repair`: the container phrase, then the repair words, `?` marking a word that cannot be read in
  either; the output is the repaired container on one line, or nothing when there is nothing to
  repair;
- `repair-words`, which needs `--count N`: the container; the output is the repair words on one
  line.

Secrets are never accepted as command-line arguments. `--stdin` also lets another program do the
asking. On Linux with systemd 249 or later, for example, `systemd-ask-password` can ask for the
secrets:

```bash
{
  systemd-ask-password --echo=no "Original seed phrase:"
  systemd-ask-password --echo=no "Password:"
  systemd-ask-password --echo=no "Repeat the password:"
} | mhfe encrypt --stdin
```

Leave out `--keyname` and `--accept-cached` there: they keep the answer in the kernel keyring for a
while after the command ends. MHFE's own prompts do the same job without that risk, so this is only
for setups that already use systemd's password agents.

With test data, the answers can also come straight from the command line, here with the public
BIP39 test phrase:

```bash
printf '%s\n%s\n%s\n' \
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' \
  'public test password' 'public test password' | mhfe encrypt --stdin
```

This suits test data only: whatever is typed on a command line stays in the shell history, and the
arguments of a program other than the shell itself show in the process list. For a real phrase, use
MHFE's own prompts or the `systemd-ask-password` example above.

The exit code tells what happened:

| Code | Meaning                                                                                             |
| ---- | --------------------------------------------------------------------------------------------------- |
| 0    | Done; for `check`, the recovery matches                                                             |
| 1    | Internal error, a failed self-test, or a failed check of a new container, which is not shown        |
| 2    | Invalid input: phrase, container, password, setting, address or option                              |
| 3    | Does not match: wrong password, PIM, memory level, container or selected length                     |
| 4    | Not enough memory for the memory level                                                              |
| 5    | Not verified (`check`): no address or fingerprint for a 24-word reading, or several lengths pass    |
| 130  | Cancelled: Ctrl+C, Escape or q at a list, Ctrl+D at a secret's prompt, SIGTERM or a closed terminal |

A command is cancelled with Ctrl+C at any moment, with Escape, or q, at a list of answers, and with
Ctrl+D on the empty prompt of a secret. Ctrl+C stops the tool at once, also in the middle of a
round; the operating system then discards its memory. SIGTERM and a closed terminal end it in the
same way at any moment, and Ctrl+\ and Ctrl+Z do so while it works; at a question they are ordinary
keys. Each first restores the terminal and leaves the private screen.

## Release files

Releases contain CLI archives for Linux (x86-64 and ARM64), macOS (Intel and Apple silicon) and
Windows (x86-64), with the program, launcher and licences, plus the browser package.

Verify the download before use. Each release from v0.5.0 includes `SHA256SUMS`, its OpenPGP
signature `SHA256SUMS.asc` and the public `RELEASE-SIGNING-KEY.asc`.
[Verification instructions](https://github.com/hobby-eng/mhfe/blob/main/docs/RELEASING.md#verify-a-downloaded-release)
give the full trusted fingerprint, key import and checksum commands; the maintainer's key is also
[public on GitHub](https://github.com/hobby-eng.gpg).

GitHub build attestations bind each archive to its source commit and workflow. Check them on the
connected computer before carrying the archive offline:

```bash
gh attestation verify mhfe-v0.6.0-linux-x86_64.tar.gz --repo hobby-eng/mhfe
```

For v0.3.0 to v0.5.0, the
[history-rewrite record](https://github.com/hobby-eng/mhfe/blob/main/docs/releases/history-rewrite-2026-10-09.md)
maps the attested old commits to the commits their tags now name.

## For developers

The [developer guide](https://github.com/hobby-eng/mhfe/blob/main/docs/DEVELOPMENT.md) covers builds,
checks, independent vectors, generated tables and the vendored Argon2 engine. The
[API guide](https://github.com/hobby-eng/mhfe/blob/main/docs/API.md) describes Rust and browser callers;
[SECURITY.md](https://github.com/hobby-eng/mhfe/blob/main/SECURITY.md) records security boundaries.

MHFE was written with extensive use of ChatGPT and Claude and went through numerous cross-checks and
audits, also made with these tools ([audit records](https://github.com/hobby-eng/mhfe/blob/main/docs/audits/README.md)).

## Questions

### Can MHFE find a missing word without the repair words?

Within limits. Enter `?` for a missing word in `decrypt`, `check`, `rekey` or `wallets`, or in
`repair`, and press Enter without a repair card. A one-word search has about 8 checksum-valid
candidates for a 24-word container or 128 for 12 words. MHFE asks what you know:

- **The container's own wallet:** give its fingerprint or a receiving/change address, and any
  BIP39 passphrase used with that container phrase. Candidates are compared directly on every CPU
  core without MHFE recovery: seconds for one word, up to minutes for two. A two-word address search
  covers the first 20 receiving and 20 change addresses of account 0; the next prompt, or
  `--scan-gap N`, extends that to 100, 500 or another count.
- **Your original wallet:** give its address or fingerprint, and its passphrase if used. Every
  candidate requires a full recovery: about a quarter of an hour for one missing word in a 24-word
  container, or two to four hours in a 12-word same-length container at the defaults.
- **The original wallet's passphrase alone:** supply it and the MHFE password, without the original
  phrase. Each recovered candidate is tested with its own checks: the short original's built-in
  check, or the optional [phrase + passphrase check](#mhfe-new), if the original was made with it.
- **Nothing:** a short original's built-in check in a 24-word container can select a candidate.
  An unchecked 24-word original or same-length container cannot identify one this way.

The reference field accepts eight hex digits as a fingerprint and otherwise an address, whose coin
is then asked. MHFE names whose passphrase it needs and asks for it only if you say it is used.
For two missing words only the container's own wallet is available; same-length containers need
that reference, or the original wallet for a one-word search. A refusal or empty result returns to
the reference choices without retyping the container. Every found word is shown before use.

Without the container-wallet reference, only one missing word is searched. Two make about 16,000
candidates in a 24-word container or 260,000 in a 12-word one: weeks, or half a year to a year, of
recoveries. MHFE shows the estimate before starting. MnemoCode's unencrypted phrases permit a much
faster two-word search with an address or fingerprint. A
[repair card](#mhfe-repair) avoids that search within its stated damage bounds.

## License

MHFE is licensed under either of the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option. Releases up to 0.6.0 were published
under the MIT license alone and remain available under it. Third-party material keeps its own
licence; see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
MHFE by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
