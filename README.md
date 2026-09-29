# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics

[![CI](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml)
[![Test vectors](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml)
[![RustSec audit](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml)

<p align="center">
  <img src="assets/mhfe-mascot.png" alt="MHFE penguin mascot carrying a cold-storage plate" width="240">
</p>

MHFE turns the recovery phrase of a Bitcoin or other BIP39 wallet (12, 15, 18, 21 or 24 English
words) into a password-protected **container of 24 words**. The container is itself an ordinary,
valid recovery phrase, so it fits the same metal plate or capsule. With the password it turns back
into your exact original phrase; without it, it reveals nothing about it. Your wallet, its addresses
and any BIP39 passphrase stay as they are.

Each recovery deliberately takes about one to two minutes and 2 GiB of memory. You wait once;
someone guessing your password pays that for every guess. An encryption takes twice as long, because
it then recovers your phrase from the new container once, to be sure the container works.

This repository is the implementation: a command-line tool, a Rust library and a browser package.
The algorithm is specified in the companion
[MHFE specification](https://github.com/hobby-eng/mhfe-spec); this version implements suite
`MHFE-BIP39-256-EXPERIMENTAL-3`.

> **Experimental.** MHFE has not been reviewed by independent cryptographers. Do not use it to
> protect real funds. Keep your original backup until you have rehearsed a recovery.

## Install

Download the archive for your system from the
[releases page](https://github.com/hobby-eng/mhfe/releases) and compare its SHA-256 with the
release's `SHA256SUMS` file:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

There are builds for Linux (x86-64 and ARM64), macOS (Intel and Apple silicon) and Windows (x86-64).
For x86-64 there are two: the standard one runs on every 64-bit x86 processor, and the one with
`ssse3` in its name is about 5% faster but needs a processor with SSSE3, which almost every computer
made since 2008 has; on one without it, it stops with a clear message. When unsure, take the
standard one. To build from source, install Rust and run `cargo build --release --locked`; the
program is then `target/release/mhfe`.

Use MHFE on a trusted computer without a network connection. It never connects to anything.

## Encrypt a recovery phrase

```text
$ mhfe encrypt

MHFE · Encrypt a recovery phrase
  Suite      MHFE-BIP39-256-EXPERIMENTAL-3
  Settings   PIM 0 · memory level 0 (2 GiB)
  Work       24 rounds (12 to encrypt, 12 to check) × 12 Argon2 passes
  Time       about 2 to 4 minutes on a current computer

Original recovery phrase (hidden):
✓ Accepted a valid 12-word phrase.
Show the words that were read? They will be visible on the screen. [y/N]:
Password (hidden):
Repeat the password (hidden):
Press Ctrl+C to cancel at any time.

Encrypting ████████████████████████  12/12  done in 1 min 59 s

Container, 24 words
┌───────────────────────────────────────────────────────────────┐
│   1. donate       2. stove        3. tower        4. picnic   │
│   5. iron         6. rescue       7. trick        8. shrimp   │
│  ...                                                          │
└───────────────────────────────────────────────────────────────┘
On one line, for copying:
donate stove tower picnic iron rescue trick shrimp roof rib home cigar ...

! Not verified yet.
! MHFE now decrypts the container again to make sure that no memory error or
! other fault changed it. You can start writing it down, but wait for the
! result before you rely on it.

Checking   ████████████████████████  12/12  done in 1 min 46 s
✓ Verified: the container turns back into your original phrase.
```

In a terminal the output is in colour; it is plain when it goes to a file or a script, or when the
environment variable `NO_COLOR` is set. The times come from a 2022 laptop with a check running
alongside.

The phrase and the password are typed without being shown, and the password is asked twice, because
a typing mistake in it would lock the phrase away for good. Words may be typed in any case and with
any spacing, and the first four letters of each word are enough, as many metal backups store them.
If you typed short forms, you can ask to see the words that were read, written out in full; they are
not shown unless you ask, because the phrase is secret.
The container appears after the first half of the work, so you can write it down while MHFE checks
it by recovering your phrase from its words. Rely on it only once it says "Verified". If the check
fails, which only a hardware or memory fault could cause, MHFE says so loudly: cross the container
out and encrypt again. With `--stdin`, or when the output goes to a file or another program, the
container is printed only after the check has passed.
The example uses the public test phrase `abandon abandon ... about` with the password
`public test password`; never use either for real funds.

Write the 24 words down. Keep the suite name too, and the PIM and memory level if you changed them:
recovery needs exactly the same values, and with anything else the container turns into a
different phrase that looks just as valid. They are not secret, and where you keep them is your
choice. Next to the container they are hardest to lose. Kept apart, for example remembered or noted
elsewhere, they do not show that the words are an MHFE container, so the container still works as a
decoy wallet.
Keep a copy of this program's release offline as well, so that a compatible version is at hand years
from now.

MHFE is deterministic: the same phrase, password and settings always give the same container. A lost
plate can therefore be made again exactly, but two identical containers made with the same password
and settings show that they hold the same phrase. Use a different password for each container; a
shared password is only as safe as the weakest container that uses it.

### Choosing a password

The password is what really protects the container. Use four or better five words chosen at random,
for example with

```text
$ mhfe password

MHFE · Make a password

  splicing icy jogging handbrake lurk

✓ 5 words from the EFF list, about 64.6 bits.
The password is shown only this once and is not stored. ...
```

The words come from the [EFF dice list](https://www.eff.org/dice) of 7,776 words. `--dice` lets you
roll real dice instead of using the computer's randomness, and `--words N` changes the number of
words. `mhfe encrypt` warns when a password is not four or more such words.

A password is ordinary text on one line. Any letters, digits, spaces and symbols in any language
are accepted, but invisible control characters such as a tab, and line breaks, are refused, so that
every program reads the password exactly as it was typed.

## Recover the original phrase

```text
$ mhfe decrypt
Container, 24 words: DONA stov towe picn iron resc ...
Read the container as:
  1. donate      2. stove       3. tower       4. picnic
  ...
Password (hidden):
...
✓ Verified: a 12-word phrase that passed its built-in check.

Recovered phrase, 12 words
┌───────────────────────────────────────────────────────────────┐
│   1. abandon      2. abandon      3. abandon      4. abandon  │
│  ...                                                          │
└───────────────────────────────────────────────────────────────┘
On one line, for copying:
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

MHFE shows the container as it read it, every word in full, so you can compare it with your backup.
For an original of 12 to 21 words, MHFE confirms the password and finds the length by itself. A
wrong password then usually shows as "Not verified": the result is read as 24 words, which is wrong
for a shorter original. An original of 24 words has no built-in check, so a wrong password gives a
different valid phrase; compare the result with your wallet.

In about one container in four billion, a phrase passes the check for two lengths. MHFE then shows
every candidate and lets you choose; `--words 12` (or 15, 18, 21, 24) selects the length yourself.

## Rehearse a recovery

Before you rely on a container, check that it recovers your wallet:

```text
$ mhfe check
...
What should the recovered phrase be compared with?
  1. A receiving address of the wallet (recommended: confirms the wallet and its passphrase)
  2. The wallet's master key fingerprint, eight hex digits (quick, weaker)
  3. Only the built-in check of a 12- to 21-word original (confirms the password, not the wallet)
Choice [1]:
Receiving address of the wallet: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
BIP39 passphrase of the wallet (hidden; press Enter if it has none):
...
✓ matches: the recovered wallet, with this BIP39 passphrase, has this receiving address.
```

The check runs a full recovery but shows only `matches` or `does not match`, never any part of the
phrase. A match says what it confirms: an address or a fingerprint identifies the wallet with its
BIP39 passphrase, while the built-in check of a 12- to 21-word original confirms only the password
and settings. With an address it looks at the first 100 receiving and change addresses of accounts 0
to 9 on the standard path of the address type (legacy `1...`, nested SegWit `3...`, native SegWit
`bc1q...`, Taproot `bc1p...`, and their testnet forms); `--path m/84'/0'/0'/0/5` checks one path. Do
not keep the address or fingerprint you check against next to the container.

## Settings: PIM and memory level

Both default to 0, and most people should leave them there. Raising them makes every recovery, yours
included, slower or more memory-hungry:

| Memory level (`--mem`) | 0     | 1     | 2     | 3     | 4     | 5      | 6      | ... 21 |
| ---------------------- | ----- | ----- | ----- | ----- | ----- | ------ | ------ | ------ |
| Memory needed          | 2 GiB | 3 GiB | 4 GiB | 6 GiB | 8 GiB | 12 GiB | 16 GiB | 3 TiB  |
| Recovery at PIM 0, min | 1–2   | 1.5–3 | 2–4   | 3–6   | 4–8   | 6–12   | 8–16   | ...    |

An encryption takes twice these times. The PIM (`--pim`, 0 to 1023) multiplies the time: PIM 1
doubles it, and at PIM 1023 a recovery takes roughly 17 to 34 hours. The computer that recovers the
container must have the memory of the chosen level; MHFE checks this before it asks for anything.
The command-line tool supports every level on a 64-bit system; a browser, and the tool on a 32-bit
system, support memory level 0 only. A higher setting adds a fixed factor, while
each extra random password word multiplies an attacker's work by 7,776, so a better password is
worth more.

## In the browser

The browser package in `dist/` (see [`web/README.md`](web/README.md)) runs the same code in a web
page, for example in the offline wallet tools. It has two modes:

- **Standard mode** works everywhere, also in a page opened as a file. Argon2 runs on one thread, so
  a recovery takes about four to seven minutes, and an encryption twice that.
- **Fast mode** runs the four Argon2 lanes in parallel, about as fast as the command-line tool. A
  browser allows this only on a specially served page. `mhfe serve tool.html` serves one HTML file
  from this computer (127.0.0.1) with the headers that enable it and opens it in the browser. It
  sees none of your secrets: all the work happens in the page. Release archives include small
  launchers that start it with a double-click. On a computer with Python 3.8 or later but without
  the mhfe program, `python3 mhfe-fast-mode.py tool.html` from the browser package does the same.
  Both serve a page only when its checksum file `mhfe-fast-mode.sha256` lies next to it and
  matches.

A browser supports memory level 0 only. It never connects to anything either: the package loads no
remote resources.

## For scripts

`--stdin` reads the answers from standard input, one per line, instead of asking:

- `encrypt`: the phrase, the password, and the password again;
- `decrypt` and `check`: the container and the password;
- `check --address` or `check --fingerprint`: then also the reference and the BIP39 passphrase
  (an empty line if the wallet has none).

Secrets are never accepted as command-line arguments. `--stdin` also lets another program do the
asking. On Linux with systemd 249 or later, for example, `systemd-ask-password` can ask for the
secrets:

```bash
{
  systemd-ask-password --echo=no "Original recovery phrase:"
  systemd-ask-password --echo=no "Password:"
  systemd-ask-password --echo=no "Repeat the password:"
} | mhfe encrypt --stdin
```

Leave out `--keyname` and `--accept-cached` there: they keep the answer in the kernel keyring for a
while after the command ends. MHFE's own prompts do the same job without that risk, so this is only
for setups that already use systemd's password agents.

The exit code tells what happened:

| Code | Meaning                                                                             |
| ---- | ----------------------------------------------------------------------------------- |
| 0    | Done; for `check`, the recovery matches                                             |
| 1    | Internal error, including an encryption whose check failed (nothing is shown then)  |
| 2    | Invalid input: phrase, container, password, setting, address or option              |
| 3    | Does not match: wrong password, PIM, memory level, container or selected length     |
| 4    | Not enough memory for the memory level, or a processor without SSSE3 for that build |
| 130  | Cancelled with Ctrl+C                                                               |

Ctrl+C stops the tool at once, also in the middle of a round; the operating system then discards its
memory.

## For developers

```bash
cargo test --locked          # fast tests with reduced Argon2 cost
scripts/check.sh             # everything, including the browser package
scripts/build-reproducible.sh
```

The library API is in [`API.md`](API.md), the security notes in [`SECURITY.md`](SECURITY.md), the
licences of the bundled Argon2 code and EFF word list in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), and timing records in
[`measurements/`](measurements/). Test vectors are written with `mhfe test-vectors` and checked
independently with `scripts/independent-suite3.py`, which uses OpenSSL's Argon2.

Argon2 is the reference C implementation of its authors, vendored unchanged in
[`vendor/phc-winner-argon2`](vendor/phc-winner-argon2.md) and used by both the native tool and the
browser package. Version 0.3.0 was the last release to implement suite 2.

On x86-64 the Argon2 code uses only SSE2, which every 64-bit x86 processor has.
`cargo build --release --features ssse3` builds it with SSSE3 instead, about 5% faster. Such a
program checks the processor before it starts Argon2 and refuses with a clear message where SSSE3 is
missing, as on some virtual machines. Both builds give byte for byte the same results; their tests
check the same values.

The Rust source is licensed under MIT; see [`LICENSE`](LICENSE).
