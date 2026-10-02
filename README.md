# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics

[![CI](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml)
[![Test vectors](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml)
[![RustSec audit](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml)

<p align="center">
  <img src="assets/mhfe-mascot.png" alt="MHFE penguin mascot carrying a cold-storage plate" width="240">
</p>

<p align="center"><sub>The penguin lives in the cold, like the backups MHFE is made for. It holds a
steel plate with 24 words and waddles from side to side, much as a Feistel network swaps its two
halves in every round.</sub></p>

MHFE turns the recovery phrase of a Bitcoin or other BIP39 wallet (12, 15, 18, 21 or 24 English
words) into a password-protected **container of 24 words**, or, if you choose so for a phrase of 12
to 21 words, a container **of the same length** as your phrase. The container is itself an
ordinary, valid recovery phrase, so it fits the same metal plate or capsule. With the password it turns back
into your exact original phrase; without it, getting the phrase back means guessing the password,
which MHFE makes deliberately slow. Your wallet, its addresses and any BIP39 passphrase stay as they
are.

Each recovery deliberately takes about one to two minutes and 2 GiB of memory. You wait once;
someone guessing your password pays that for every guess. An encryption takes twice as long, because
it then recovers your phrase from the new container once, to be sure the container works.

This repository is the implementation: a command-line tool, a Rust library and a browser package.
The algorithm is specified in the companion
[MHFE specification](https://github.com/hobby-eng/mhfe-spec); this version implements suite
`MHFE-BIP39-256-EXPERIMENTAL-3` for 24-word containers and, since version 0.5.0, suite
`MHFE-BIP39-LP-EXPERIMENTAL-4` for containers of the same length.

> **Experimental.** MHFE has not been reviewed by independent cryptographers. Do not use it to
> protect real funds. Keep your original backup until you have rehearsed a recovery.

## How it works

MHFE is made for **cold storage**: a backup of a recovery phrase that is written once on paper or a
metal plate, put away, and read again perhaps years later on an offline computer. It is not meant
for a wallet in daily use.

**Any phrase becomes 24 words.** MHFE accepts a phrase of 12, 15, 18, 21 or 24 words and always
gives a container of 24 words. Inside, the original becomes a 256-bit number that twelve rounds of a
Feistel cipher scramble. Each round takes its key from the password through Argon2id, with 2 GiB of
memory, and needs the result of the round before, so every guess of the password costs the full
work. The result is written out as 24 words with an ordinary BIP39 checksum: the container is itself
a valid recovery phrase, fits the same plates, and nothing in it shows that MHFE made it. No salt,
version or length is stored; with the default settings, the 24 words and the password are all you
need.

**Checksums.** The container's BIP39 checksum catches most mistakes in copying it; one wrong word
slips through in about one case in 256. An original of 12 to 21 words leaves room in the 256 bits,
and MHFE fills it with a hash of the original, a built-in check: on recovery it confirms the
password and settings and finds the length of the original by itself, so MHFE almost always tells you
when the password is wrong. A 24-word original fills all 256 bits and has no built-in check: every
password gives some valid phrase, and only a comparison with the wallet shows whether it is yours.

**12 to 21 words, or 24?** The length is that of your wallet's phrase. If you are creating a new
wallet for cold storage, choose it with this in mind:

| Original       | On recovery                                                          | Suits                                                                       |
| -------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| 12 to 21 words | The built-in check confirms the password and finds the length        | Most backups: MHFE tells you when the password or a setting is wrong        |
| 24 words       | No built-in check: a wrong password gives another, equally valid one | Use with an independent BIP39 passphrase, and plausible deniability (below) |

**Or a container of the same length.** For a phrase of 12, 15, 18 or 21 words, MHFE can instead
give a container with as many words as the phrase, if you choose it; 24 words stays the default.
The backup then keeps its length and looks like any other phrase of that length. The price is
real, so MHFE asks first and explains it (press `?` at the question):

| Container             | A wrong password                             | Shows the length of your phrase | A miscopied word slips through                |
| --------------------- | -------------------------------------------- | ------------------------------- | --------------------------------------------- |
| 24 words (default)    | is detected: MHFE tells you (12 to 21 words) | no, every container has 24      | about once in 256                             |
| Same length as phrase | gives another valid phrase, with no error    | yes                             | about once in 16 (12 words) to 128 (21 words) |

The same-length container has no room for a built-in check, so only a comparison with your wallet,
with `mhfe check`, confirms a recovery. Like a 24-word original, it turns into a valid phrase with
any password. The [specification](https://github.com/hobby-eng/mhfe-spec) defines this format as
suite 4; its analysis of plausible deniability covers this format too, while its estimates of what
an attack costs are stated for the 24-word format only.

The built-in check helps you, but it also lets someone who has the container recognise a right
guess; each guess still costs a full recovery. With 24 words, every password gives a valid phrase,
and the container alone cannot tell a right password from a wrong one. A guesser can recognise the
right one only through a wallet with a public history. If the wallet of the phrase itself, used
without a BIP39 passphrase, has ever received funds, its history on the blockchain confirms a right
password. If you use the phrase only with a BIP39 passphrase and the wallet without it has never
been used, the blockchain gives no hint, and the password and the passphrase have to be guessed
together.

**Checking against your wallet.** The built-in check confirms the password, not which wallet the
phrase belongs to, and a 24-word result or a same-length container cannot check itself at all. `mhfe check` therefore
compares a recovery with a receiving address of the wallet or its master key fingerprint, without
showing the phrase (see [Commands](#commands)).

**Plausible deniability.** The container is a valid phrase in its own right, so it can open a small
decoy wallet; that fools only someone who does not know that MHFE was used. A 24-word original
offers more: any other password turns the same container into another valid 24-word phrase. Recover
the container once with a decoy password, chosen as randomly as the real one, and use the wallet it
gives as a decoy with a believable balance and history. Under pressure you can hand over that
password; nothing in the container or in what MHFE shows tells it apart from the real one, because
every 24-word result is shown as not verified. The
[specification](https://github.com/hobby-eng/mhfe-spec) analyses this and its limits: it does not
help if the other side knows that your original has fewer than 24 words, every copy of the backup
must be an exact copy of the same container, and no other record of the phrase, such as a paper copy
or a hardware wallet, may contradict what you hand over. Like the rest of MHFE, this analysis has
not been independently reviewed.

## Ways to use it

> [!WARNING]
> **The MHFE password is not your BIP39 passphrase!** A BIP39 passphrase, sometimes called the 25th
> word, belongs to the wallet: a wallet asks for it together with the recovery phrase, and it stays
> the same after MHFE. The MHFE password only opens the container.
>
> **Every password and passphrase in this tree must be different!** The MHFE password, a decoy MHFE
> password, a decoy passphrase and the passphrase of your wallet are separate secrets. Never use one
> text twice and never make one from another; whoever found one would then have the others.

The same 24 words on the plate open different wallets, depending on what is typed with them. Every
branch but the last is optional; the last one leads to your real wallet.

```text
24-word container on the plate
│
├── typed into a wallet as it is
│   ├── without a BIP39 passphrase ........... decoy wallet, a small amount or nothing
│   └── with a decoy BIP39 passphrase ........ prepared decoy wallet with believable funds
│
├── recovered by MHFE with a decoy password    (24-word originals only)
│   └── another valid phrase ................. decoy wallet behind an "MHFE password"
│
└── recovered by MHFE with your password
    └── your original recovery phrase
        ├── without a BIP39 passphrase ....... your wallet
        └── with its own BIP39 passphrase .... your wallet: the strongest arrangement
```

**The container as a wallet.** Every wallet accepts the 24 words as an ordinary recovery phrase.
Leave that wallet empty, or keep a small amount on it so that the plate looks like an ordinary
backup. Anyone who reads the plate can spend that amount, and the decoy convinces only someone who
does not know that MHFE was used. Type the container only into a wallet you trust, such as a
hardware wallet: like the plate, any copy of it lets its holder try passwords offline.

**A decoy passphrase for the container.** Add a BIP39 passphrase to the container's wallet in
advance and put a believable amount on the wallet it opens. Asked for your passphrase, you can give
this one. Whoever has the plate and this passphrase can spend that amount, so keep it to what you
can afford to lose.

**A decoy MHFE password, for a 24-word original.** As described in
[plausible deniability](#how-it-works), any other password turns the container into another valid
phrase. Recover the container once with a decoy password, chosen as randomly as the real one, and
use the wallet it gives as a decoy. This holds even against someone who knows that MHFE was used,
because every password gives an equally valid 24-word phrase, as long as the decoy wallet's balance
and history look like those of a wallet in real use.

**Your original phrase.** With your password, MHFE gives back the exact original, and your wallet
opens as before. The strongest arrangement is a 24-word original with its own BIP39 passphrase,
independent of the MHFE password, while the wallet of the original without a passphrase stays
unused: whoever has the container must then guess the password and the passphrase together, and
the blockchain gives no hint which guess is right. Every secret you add is one more that you must
not forget: a lost passphrase loses the wallet just as a lost password does.

## Getting started

Nothing is installed. Download the archive for your system from the
[releases page](https://github.com/hobby-eng/mhfe/releases) ([which one](#release-files)), unpack it
and run `mhfe` in a terminal: `mhfe encrypt`, `mhfe decrypt` and the other commands that
`mhfe --help` lists. Started without a command, by a double-click or with the `mhfe-launch` script
in the archive, it shows a menu of the same commands with their default settings.

Use it on a trusted computer that stays offline while the phrase and the password are on it, best a
Linux system started from a USB stick with the network off. On Windows, Windows PE from a USB stick
is better than your everyday system; `mhfe.exe` needs nothing beyond Windows itself, though it has
not been tested in Windows PE yet.

## Commands

**`mhfe password`** makes a password of random words from the
[EFF dice list](https://www.eff.org/dice) of 7,776 words: use four, better five. `--dice` uses real
dice, `--words N` sets the count. Any text on one line can be a password, but control characters
such as a tab are refused, and letter case and spaces count. The password is not your wallet's
BIP39 passphrase.

**`mhfe encrypt`** asks for the phrase and twice for the password, all hidden; a mistyped password
would lock the phrase away for good. For a phrase of 12 to 21 words it first asks how long the
container should be: 24 words, the recommended default, or the same length as your phrase; `?`
explains both, and `--same-length` chooses the same length without asking. After the encryption it
shows the format of the container, the suite identifier. The words of the recovery phrase may be typed in any case or as
their first four letters; the password, by contrast, must be typed exactly, letter case and spaces
included. On request MHFE shows the phrase it read, or the password, on a separate screen that is
cleared afterwards. The container appears after one to two minutes: write it down while MHFE checks
it by recovering your phrase from it, and rely on it only once it says "Verified". With the default
settings the container's words and the password are all you need; in the rare case that MHFE asks
you to note the word count, do so. The same phrase, password and settings always give the same container, so a
lost plate can be made again, and two identical containers reveal the same phrase: use a different
password for each phrase.

**`mhfe check`** rehearses a recovery before you rely on a container and shows only "matches" or
"does not match", never the phrase. Type the container from the plate, not from the screen: one
miscopied word passes the BIP39 checksum in one case in 256, or as often as one in 16 for a
12-word container of the same length, and for a 24-word original or a same-length container
silently gives another wallet. A same-length container has no built-in check, so compare it with
your wallet. Compare with a receiving address of the wallet, the strong check that also
covers a BIP39 passphrase (it searches the first 100 receiving and change addresses of accounts 0 to
9, or one path with `--path`), or with the master key fingerprint, quick but only 32 bits. Do not
keep the address or fingerprint next to the container.

**`mhfe decrypt`** gives back the original phrase. It shows the container as it read it, to compare
with your backup, its format, and the phrase on a separate screen that is cleared when you press
Enter. The number of words tells it the format: 24 words is the default format, 12 to 21 words a
container of the same length. For a 12- to 21-word original in a 24-word container it confirms the
password and finds the length itself; a wrong password then shows as "Not verified". A 24-word
original and a same-length container have no such check: a wrong password gives another valid
phrase, so compare the result with your wallet. `--words N` sets the length of the original
yourself; it then accepts only a 24-word container or a same-length container of exactly N words.

`mhfe <command> --help` explains every option. Keep a copy of this program offline as well, so that
a compatible version is at hand years from now.

## Settings: PIM and memory level

Both default to 0, and most people should leave them there. Raising them makes every recovery, yours
included, slower or more memory-hungry:

| Memory level (`--mem`) | 0     | 1     | 2     | 3     | 4     | 5      | 6      | ... 21 |
| ---------------------- | ----- | ----- | ----- | ----- | ----- | ------ | ------ | ------ |
| Memory needed          | 2 GiB | 3 GiB | 4 GiB | 6 GiB | 8 GiB | 12 GiB | 16 GiB | 3 TiB  |
| Recovery at PIM 0, min | 1–2   | 1.5–3 | 2–4   | 3–6   | 4–8   | 6–12   | 8–16   | ...    |

An encryption takes twice these times. The PIM (`--pim`, 0 to 1023) multiplies the time: PIM 1
doubles it, and at PIM 1023 a recovery takes roughly 17 to 34 hours. The computer that recovers the
container must have the memory of the chosen level; MHFE checks this before it asks for anything,
on Linux also against the memory limit of a container or a systemd unit it runs in.
The command-line tool, which needs a 64-bit system, supports every level; a browser supports memory
level 0 only. A higher setting adds a fixed factor, while each extra random password word multiplies
an attacker's work by 7,776, so a better password is worth more.

> [!WARNING]
> **Changed the PIM or the memory level? Remember the values!** With the defaults, both 0, the 24
> words and the password are all you need. A container made with other values opens only with
> exactly those values; with any others it turns into a different phrase that looks just as valid,
> and nothing in the container tells which values were used. A forgotten value then has to be found
> by trying one value after another (PIM 0 to 1023, memory level 0 to 21), each try a full recovery
> that takes longer the higher the value, and for a 24-word original each result must also be
> compared with your wallet.

## In the browser

The browser package in `dist/` (see [`docs/BROWSER-PACKAGE.md`](docs/BROWSER-PACKAGE.md)) runs the
same code in a web page, for example in the offline wallet tools. It has two modes:

- **Standard mode** works everywhere, also in a page opened as a file. Argon2 runs on one thread, so
  a recovery takes about four to seven minutes, and an encryption about twice that.
- **Fast mode** runs the four Argon2 lanes in parallel, about a quarter slower than the command-line
  tool. A browser allows this only on a specially served page. `mhfe serve tool.html` serves one
  HTML file from this computer (127.0.0.1) with the headers that enable it and opens it in the
  browser. It sees none of your secrets: all the work happens in the page. When a tool and its
  checksum file lie next to the program, the first entry of its menu serves that tool, so a
  double-click is enough. On a computer with Python 3.8 or later but
  without the mhfe program, `python3 mhfe-fast-mode.py tool.html` from the browser package does the
  same. Both serve a page only when its checksum file `mhfe-fast-mode.sha256` lies next to it and
  matches.

A browser supports memory level 0 only. It never connects to anything either: the package loads no
remote resources.

Both kinds of container work there too: a page asks for the same length with `sameLength: true`
in its `encrypt` call, and recovery takes either kind.

## For scripts

`--stdin` reads the answers from standard input, one per line, instead of asking:

- `encrypt`: the phrase, the password, and the password again; the container has 24 words unless
  `--same-length` is given;
- `decrypt`: the container and the password;
- `check`: the container and the password, then with `--address` or `--fingerprint` the reference
  and the BIP39 passphrase (an empty line if the wallet has none); with `--words N` nothing more.
  `check --stdin` needs one of these three options, because it cannot ask which reference to use.

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

| Code | Meaning                                                                            |
| ---- | ---------------------------------------------------------------------------------- |
| 0    | Done; for `check`, the recovery matches                                            |
| 1    | Internal error, including an encryption whose check failed (nothing is shown then) |
| 2    | Invalid input: phrase, container, password, setting, address or option             |
| 3    | Does not match: wrong password, PIM, memory level, container or selected length    |
| 4    | Not enough memory for the memory level                                             |
| 130  | Cancelled with Ctrl+C                                                              |

Ctrl+C stops the tool at once, also in the middle of a round; the operating system then discards its
memory.

## Release files

A release has archives for Linux (x86-64 and ARM64), macOS (Intel and Apple silicon) and Windows
(x86-64), each with the `mhfe` program, its launcher and the licences, and the browser package. One
x86-64 program fits every 64-bit x86 processor: it uses SSSE3 where the processor has it, 7 to 10%
faster ([measured](docs/measurements/README.md)), and SSE2 otherwise.

Check a download against the release's `SHA256SUMS` before you use it:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

## For developers

To build from source, install Rust and run `cargo build --release --locked`; the program is then
`target/release/mhfe`.

```bash
cargo test --locked          # fast tests with reduced Argon2 cost
scripts/check.sh             # everything, including the browser package
npm ci --ignore-scripts && npm run format:check   # Prettier for Markdown and JavaScript
npm run check:browsers       # the browser package in Chromium and Firefox, after check.sh
scripts/build-reproducible.sh
```

The library API is in [`docs/API.md`](docs/API.md), the security notes in
[`SECURITY.md`](SECURITY.md), the licences of the bundled Argon2 code, EFF word list, browser
JavaScript runtime and Rust crates in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) (its crate
list is written by `scripts/third-party-licenses.py`; every release archive carries the file), and
timing records in [`docs/measurements/`](docs/measurements/).
Test vectors are written with `mhfe test-vectors` (`--same-length` for the suite 4 set in
`tests/fixtures/suite4-vectors`) and checked independently with `scripts/independent-suite3.py`
and `scripts/independent-suite4.py`, which use OpenSSL's Argon2 and the Unicode 17.0.0 database of
`unicodedata2`; their packages install with
`python3 -m pip install --require-hashes -r scripts/independent-suite3-requirements.txt`, and
`python3 scripts/independent-suite3.py passwords tests/fixtures/validation-cases.json` checks the
password rule on every case of the specification.

Argon2 is the reference C implementation of its authors, vendored unchanged in
[`vendor/phc-winner-argon2`](vendor/phc-winner-argon2.md) and used by both the native tool and the
browser package. Version 0.3.0 was the last release to implement suite 2.

On x86-64 the Argon2 code is compiled twice, with SSE2, which every 64-bit x86 processor has, and
with SSSE3, 7 to 10% faster in the [measurements](docs/measurements/README.md). The program checks
the processor and runs the SSSE3 copy only where SSSE3 is present, so it also runs on older AMD
processors and on virtual machines that hide SSSE3. Both copies give byte for byte the same
results, and the tests run both.

The Rust source is licensed under MIT; see [`LICENSE`](LICENSE).

MHFE was written with extensive use of ChatGPT and Claude and went through numerous cross-checks and
audits, also made with these tools ([`docs/audits/`](docs/audits/README.md)).
