# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics

[![CI](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml)
[![Release](https://github.com/hobby-eng/mhfe/actions/workflows/release.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/release.yml)
[![RustSec audit](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml)
[![Build provenance: GitHub attestations](https://img.shields.io/badge/build%20provenance-GitHub%20attestations-2ea44f)](https://github.com/hobby-eng/mhfe/attestations)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<p align="center">
  <img
    src="https://raw.githubusercontent.com/hobby-eng/mhfe/main/assets/mhfe-mascot.png"
    alt="MHFE penguin carrying a metal backup"
    width="240"
  >
</p>

<p align="center">
  <sub>The penguin lives in the cold, like the backups MHFE is made for. It holds a
    steel backup with 24 words and waddles from side to side, much as a Feistel network swaps its
    two halves in every round.</sub>
</p>

MHFE encrypts a wallet's English BIP39 seed phrase into a password-protected **container phrase**.
The container is itself a valid BIP39 phrase, so you can write it on the same paper or metal backup.
Recovering it with your password gives back the exact original seed phrase. Your wallet's addresses
and BIP39 passphrase stay the same.

It accepts 12, 15, 18, 21 or 24 words and makes a 24-word container by default. For a shorter
phrase, you can choose a container of the same length. At the default settings, recovery takes
roughly one to two minutes and 2 GiB of memory on a current computer. Encryption takes about twice
as long: MHFE recovers the new container to check it before finishing.

> [!WARNING]
> MHFE is experimental and has not been reviewed by independent cryptographers. Keep your original
> backup until you have rehearsed a recovery from the container you wrote down.

The [documentation index](https://github.com/hobby-eng/mhfe/blob/main/docs/README.md) lists the user guides and developer references.
The [specification](https://github.com/hobby-eng/mhfe-spec) defines the protocol;
[mhfe-core](https://github.com/hobby-eng/mhfe_core) implements its cipher. This repository provides
an offline command-line tool, a Rust library and a browser package built on that core.

<a id="release-files"></a>

## Getting started

Download and unpack the archive for your system from
[Releases](https://github.com/hobby-eng/mhfe/releases). Before running it, follow
[download verification](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#release-files). The release signing key fingerprint is
`28FC51B1DB80DF2101128CB30EDD4814591DD095`.

There is nothing to install. On Linux, after verification:

```bash
chmod +x mhfe
./mhfe
```

On Windows, run `mhfe.exe`; the archive also includes a launcher. The examples below use `mhfe` for
the program's name or path. To build it yourself, see [Building and checking
MHFE](https://github.com/hobby-eng/mhfe/blob/main/docs/DEVELOPMENT.md).

> [!WARNING]
> **The MHFE password is not your BIP39 passphrase!** A BIP39 passphrase, sometimes called the 25th
> word, belongs to the wallet: a wallet asks for it together with the seed phrase, and it stays
> the same after MHFE. The MHFE password only opens the container.
>
> **Every password and passphrase must be different!** The MHFE password, every other MHFE
> password, every decoy passphrase and the passphrase of each wallet are separate secrets. Never
> use one text twice and never make one from another; whoever found one would then have the
> others.

**Recommended workflow:** boot a trusted, non-persistent Linux live system from a USB stick or
Live CD, disconnect networking, and run MHFE's interactive commands in its terminal. Type your
answers at the prompts; `--stdin` and `systemd-ask-password` are optional tools for scripts, not
setup steps for this workflow. When finished, shut down or reboot the live system.

A non-persistent live session is discarded on reboot. This does not erase files you saved to an
attached disk or copies written to disk-backed swap. The swap protections below still apply.
For a Windows-only setup, prefer a separate offline environment; MHFE needs no runtime beyond
Windows itself, but has not been tested in Windows PE.

Before asking for secrets, MHFE applies the process protections the system offers and warns when
one fails. On Windows it cannot close the network itself. These restrictions do not make an
everyday or compromised computer trustworthy.

It then runs its startup self-test, comparing every part of the program with known answers. Word
lists, keys and addresses are checked against values computed with independent implementations,
among them [@scure/bip39](https://github.com/paulmillr/scure-bip39), audited by Cure53, and the
other audited @scure and @noble libraries that the multi-chain wallet tools use.

Memory can reach disk through swap or hibernation. On Linux MHFE tries to forbid itself swap;
where it cannot and swap is not encrypted, it asks whether to continue. It also warns when secret
memory cannot be locked. On Windows use BitLocker or no page file; macOS encrypts its swap. See
[Security](https://github.com/hobby-eng/mhfe/blob/main/SECURITY.md#swap-and-hibernation) for the protections and limits on each system.

<a id="commands"></a>

## Menu

Run `mhfe` without arguments in a terminal, or open its launcher. Choose with the arrow keys and
Enter, or press the entry's number. The sections below follow the menu order; the program's **More**
links open the relevant section.

| Menu | Task                         | What it does                                                 |
| ---- | ---------------------------- | ------------------------------------------------------------ |
| 1    | [Encrypt](#mhfe-encrypt)     | Put an existing seed phrase into a container                 |
| 2    | [Decrypt](#mhfe-decrypt)     | Recover one or more seed phrases from a container            |
| 3    | [Check](#mhfe-check)         | Rehearse a recovery without showing the phrase               |
| 4    | [Rekey](#mhfe-rekey)         | Make a replacement container with a new password or settings |
| 5    | [Repair](#mhfe-repair)       | Repair a damaged container or make its repair words          |
| 6    | [Password](#mhfe-password)   | Make a password with random words, characters or real dice   |
| 7    | [Self-test](#mhfe-self-test) | Check this installation against known answers                |
| 8    | [Help](#help)                | Read commands and options                                    |
| —    | [Quit](#quit)                | Leave the program                                            |

When a browser tool and its checksum file lie next to the program, **Fast mode** appears first and
all other entries move down by one. It opens that tool in the browser; see [In the
browser](#in-the-browser).

### Typing and reading secrets

At a terminal that supports it, secrets appear on a private screen that clears when you leave it.
This is the terminal's alternate screen: it keeps those lines out of the main screen's scrollback,
but cannot prevent someone watching, recording or logging the terminal. The main screen keeps a
short summary when the command ends.

BIP39 words accept any letter case and their first four letters. Hints below the current word show
how many words start with one letter, then list matches from two letters. Tab completes BIP39 words;
Ctrl+W deletes the last word. A password is exact text: case and spaces count, and Tab remains part
of it and is refused as a control character. Its hints use the EFF word list.

Under a displayed seed phrase or container, MHFE shows the wallet's master key fingerprint: eight
hexadecimal digits, called "Master fingerprint" in Sparrow. They do not reveal the phrase. The label
says whether a BIP39 passphrase was used. A container's fingerprint belongs to its own words, not
to your original wallet; a hidden wallet's fingerprint appears only with its phrase.

Where no private screen is available, such as `TERM=dumb`, secret input has no echo, container input
remains visible, and requested output may stay on the main screen. Decryption then offers one
password only. [Terminal input and
cancellation](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#terminal-input-and-cancellation) describes these cases and the keys that
stop a command.

## `mhfe encrypt`

```bash
mhfe encrypt
mhfe encrypt --pim 1 --mem 0 --new-password words --repair-words 4
mhfe encrypt --pim 0 --mem 0 --same-length --repair-words 4
```

[More CLI examples](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#1-encrypt).

Encrypt an existing seed phrase. First choose [PIM and memory
level](#settings-pim-and-memory-level), then type the phrase. For 12 to 21 words, choose a 24-word
container or one of the same length. The default is 24 words; `?` explains the difference, and
`--same-length` selects the shorter format directly.

Next, MHFE offers [repair words](#mhfe-repair), recommending four; `--repair-words N` answers in
advance, with 0 for none. Finally, type a password twice, or have MHFE [make one](#mhfe-password).
A generated password must be typed back from your written copy before it is used.

After the first twelve rounds, the container appears on a private screen marked **not yet
verified**. Write it down while MHFE recovers it and compares the result with your original seed
phrase. Rely on it only after **Verified** appears. A failed or cancelled check leaves that
container unchecked. Enter or Escape clears the screen once you have copied and checked the words.
Output to a file or another program contains only a container whose creation check passed.

The summary names the container format and lists what to keep: the container, its password, any
BIP39 passphrase of the wallet, and repair words, changed settings or word count where needed. MHFE
encrypts the phrase only; it does not ask for or store an existing wallet's passphrase.

Before relying on the backup, run [Check](#mhfe-check) using the words you wrote down, not the ones
still on screen. Keep the original backup until that rehearsal matches.

### 24 words or the same length

| Container                       | Recovery check                                           | Length revealed | Chance a miscopied word passes the BIP39 checksum |
| ------------------------------- | -------------------------------------------------------- | --------------- | ------------------------------------------------- |
| 24 words, default               | Built-in check for a 12- to 21-word original seed phrase | No              | About 1 in 256                                    |
| Same length, for 12 to 21 words | No built-in check; compare with the wallet               | Yes             | About 1 in 16 to 1 in 128                         |

A 24-word original seed phrase also has no built-in check. For it, or for a same-length container,
every password gives a valid phrase. **Not verified** means you must compare the recovery with your
wallet; a valid BIP39 checksum alone cannot do that.

The default format is named `MHFE-BIP39-256-EXPERIMENTAL-3`; the same-length format is
`MHFE-BIP39-LP-EXPERIMENTAL-4`. The [protocol guide](https://github.com/hobby-eng/mhfe/blob/main/docs/HOW-IT-WORKS.md) explains the built-in
check and why the specification's attack-cost estimates for 24-word containers do not cover
same-length containers.

## `mhfe decrypt`

```bash
mhfe decrypt
mhfe decrypt --pim 1 --mem 0 --words auto --passphrase-used no
mhfe decrypt --pim 0 --mem 0 --repair --words auto
```

[More CLI examples](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#2-decrypt).

Recover the original seed phrase from a container. Choose its settings, type the container and enter
the password. The word count identifies the format: 24 words for the default format, 12 to 21 for
the same-length format.

For a 24-word container, MHFE checks each possible shorter original length. A passing built-in check
selects the length and marks that reading **Verified**; no passing check leaves the 24-word reading
**Not verified**. A same-length container always gives an unverified phrase. Compare unverified
results with your wallet.

For a 24-word container, unless `--words` states 12 to 21, MHFE asks before work starts whether
the original wallet uses a BIP39 passphrase. For every 24-word reading it reports whether the
phrase + passphrase check passes. A failure matters only if the wallet was made with that check; a
phrase made without it almost always fails. A pass does not identify the wallet.
`--passphrase-used yes|no` answers the question in advance.

`--words N` states the original length. A passing built-in check can overrule it, and MHFE says
which length it found. If you state 24 words but a shorter check passes, both readings appear.
Several shorter checks can also pass by rare chance, roughly once in four billion containers.
Compare these readings with an address of the wallet. A stated length accepts only a 24-word
container or a same-length container of exactly that length.

<a id="mhfe-wallets"></a>

### Several passwords and hidden wallets

At a private terminal, after the first password and the question about the original wallet's
BIP39 passphrase, MHFE offers to recover now or add another password, and again after each one
added. Each password has its own PIM and memory level; Enter accepts the **first password's
settings**. All questions come before the work.

Each result appears under its password as soon as it is recovered, so you can read it while the
next recovery runs. Once all are finished, scroll with the arrow keys or Page Up and Page Down;
the mouse wheel also works in terminals that translate it to those keys. Enter or Escape clears
the screen. MHFE keeps the scrollable lines in memory it attempts to lock and wipes them when the
screen closes.

MHFE first tries to reserve the memory needed by the highest selected level. If that fails, it can
continue with the first password's level; recoveries needing more memory are skipped, with an
explanation on the private screen. Extra passwords, their settings, progress and results stay out
of the main-screen summary, including after cancellation. There is no command-line option recording
how many to try. Without a private screen, or with a stated 12- to 21-word original length for a
24-word container, MHFE asks for one password only.

Other passwords give other valid phrases: usually 24 words from a 24-word container, or the
container's own length from a same-length one. You can use one as a **hidden wallet** behind the
wallet you could disclose. Nothing is created or stored: the same container, password and settings
give the same phrase each time. This is part of `mhfe decrypt`; there is no `mhfe wallets` command.

A hidden wallet depends on the exact container. Rekeying, changing the container format, forgetting
its password or settings, or losing every copy of the container loses access to it unless you moved
its funds first. Run `mhfe self-test --vectors` on a computer before funding such a wallet, so a
build that computes the protocol wrongly does not give you a wallet other implementations cannot
recover.

Use a separate strong password for each wallet. Keep hidden wallets free of links to you or your
main wallet, including transfers and watch-only copies on everyday devices. Choose a password whose
reading is **Not verified** and fails the 16-bit check with the main wallet's passphrase, or with
none if it has none. A random reading passes that check about once in 65,536; choose another
password if it does. [Hidden wallets and decoys](https://github.com/hobby-eng/mhfe/blob/main/docs/HOW-IT-WORKS.md#hidden-wallets-and-decoys)
explains what can remain hidden and when a decoy password can stand in for yours.

## `mhfe check`

```bash
mhfe check --pim 0 --mem 0 --address
mhfe check --pim 0 --mem 0 --fingerprint
mhfe check --pim 0 --mem 0 --words 12
```

[More CLI examples](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#3-check).

Rehearse recovery from the finished backup without showing the seed phrase. Use a receiving address
from your wallet for the strongest check, or its master key fingerprint for a 32-bit comparison.
Keep that reference apart from the container.

The questions come in this order: settings, container, MHFE password, the original wallet's BIP39
passphrase, then what to compare with. The passphrase comes before the address or fingerprint even
when `--address` or `--fingerprint` chose the reference kind. A specific `--words N` check needs no
passphrase. [Script input](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#for-scripts) lists the input order for each option.

MHFE identifies possible coins from the address. Forms shared by several coins are searched as each:
`1…` as Bitcoin and Bitcoin Cash, `3…` as Bitcoin and Litecoin, `0x…` as Ethereum and Ethereum
Classic. `--coin` restricts this to one coin. Before work, the screen names the coins and search
range: normally accounts 0 to 9, the first 100 receiving and change addresses on the standard paths,
or the single path given by `--path`. See [Supported wallet
references](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#supported-wallet-references) for the coin list and address limits.

The result is **matches**, **does not match** or **not verified**. A matched address includes the
path where it was found. With a passphrase, MHFE compares that wallet first, then the wallet without
it. A match of the latter confirms the phrase only; MHFE says when the passphrase is still
unconfirmed, and that `mhfe rekey` takes only a reference of the wallet with the passphrase. If the
phrase + passphrase check also passes, it reports that evidence separately.

A 24-word container can instead be checked using the original phrase's own checks:

- **The container's built-in check** applies to original lengths of 12 to 21 words. A matching
  length takes precedence over a different length you stated. **Detect automatically**, or
  `--words auto`, tries the lengths and also evaluates the 24-word reading with the passphrase.
  When no length matches, MHFE asks for the original length.
- **The phrase + passphrase check** is offered only after a passphrase was typed. A pass gives
  statistical evidence of the right password and passphrase, but the result remains **not
  verified**: use an address or fingerprint to identify the wallet.

A mismatch cannot tell which input was wrong: the container, password, settings, passphrase or
reference. A same-length container has no built-in check and needs a wallet reference.

## `mhfe rekey`

```bash
mhfe rekey
mhfe rekey --pim 0 --mem 0 --new-pim 1 --new-mem 0 --new-password check-word
```

[More CLI examples](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#4-rekey).

Make a replacement container for the same seed phrase with a new password, settings or both. Choose
the old settings, type the container, state the original word count or select **Detect
automatically** (`--words auto`), then enter the old password. The replacement uses the old
container's format.

MHFE confirms the recovered phrase before encrypting it again. A unique built-in check at the
12- to 21-word length you stated can confirm it. Otherwise choose a wallet address, its fingerprint,
or **I know neither: show me the phrase**. That last choice requires a private screen and an
independent written backup or your wallet for comparison; memory alone is weak evidence. Some
ambiguous readings can be distinguished only by an address or fingerprint. `--confirm
check|address|fingerprint|show` chooses the method in advance.

MHFE asks whether the wallet has a BIP39 passphrase so its list of what to keep is complete. Neither
answer is preselected. When confirming by address or fingerprint, type that passphrase before the
reference; an empty one is refused if you said the wallet has one. Then choose the new settings and
password. For an original without a built-in check, MHFE also gives a fingerprint to rehearse the
replacement with `mhfe check --fingerprint`.

**The old container still works.** Rehearse recovery from the replacement before deciding what to
keep. Other passwords on the old container open different wallets on the new one. Keep the old
container, those passwords and their settings until you have moved their funds; your original
wallet keeps its addresses.

## `mhfe repair`

```bash
mhfe repair
mhfe repair-words --count 4
```

[More CLI
examples](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#5-repair-and-repair-words).

Repair words are extra words computed from a container. Keep them on a separate repair card: one
repair word restores one unreadable word, while two restore one wrong word.

| Repair words | Unreadable words repaired | Or wrong words repaired |
| ------------ | ------------------------- | ----------------------- |
| 2            | 2                         | 1                       |
| 4            | 4                         | 2                       |
| 6            | 6                         | 3                       |
| 8            | 8                         | 4                       |

The menu offers both repairing a container and making a card for an existing one (`mhfe
repair-words`). Creation commands also offer a card. It appears only after the container's check
passes, labelled `MHFE-REPAIR-1`, with numbered words such as `1/4` to `4/4`. A changed container
needs a new card.

Type the damaged container, using `?` for unreadable words, then the card, also with `?` where
needed. You can type its profile name and word numbers as written; four letters of a word are
enough. MHFE shows the repaired container and every change. Correct your written backup, then
rehearse recovery with `mhfe check`. A repair that passes the BIP39 checksum does not establish that
this is your intended container: excess damage or a card from another backup can sometimes give a
wrong checksum-valid result.

You can also repair inside `decrypt`, `check` or `rekey`: `?` prompts for the card immediately, and
`--repair` asks for it after the container. The repaired words are used only after you choose
**Use it**. The summary records positions changed, never the words.

Protect the card like a partial copy of the container and keep it apart from the backup. Together
with a damaged container it may restore enough for someone to guess passwords. Alone, it still
narrows possible containers; see [Repair-card limits](https://github.com/hobby-eng/mhfe/blob/main/docs/HOW-IT-WORKS.md#repair-card-limits).

### Without the repair words

Type `?` for a missing word and press Enter at the repair-card question. MHFE asks what you know:

| What you have                                        | Search                                                                                                      |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Address or fingerprint of the container's own wallet | Compare candidates directly, without a password or Argon2; one or two missing words                         |
| Address or fingerprint of your original wallet       | Recover each candidate with your password; one missing word only                                            |
| The original wallet's BIP39 passphrase               | Try the original phrase's built-in check and, for a 24-word reading, its optional phrase + passphrase check |
| Neither reference nor passphrase                     | Use the built-in check of a 12- to 21-word original in a 24-word container                                  |

A reference field accepts eight hexadecimal digits as a fingerprint, otherwise an address. The
passphrase question names whose wallet is being compared and comes before the reference. For two
missing words only the container's own wallet is offered; for same-length containers the original
phrase's own checks are unavailable.

For one missing word, a 24-word container has about eight candidates and a 12-word container
about 128. Comparing the container's own wallet takes seconds on all native processor cores.
Recovering each candidate instead takes about fifteen minutes for the first case and two to four
hours for the second, at default settings. MHFE states the estimate before work and shows found
words before using them. After a failed search it asks what you know again, keeping the container
you typed.

For two missing words, an address search starts with the first account's first 20 receiving and
change addresses, then offers 100, 500 or your own gap (`--scan-gap N`). Recovering every candidate
with your password would take weeks to months, so that search is not offered. Repair words avoid
these searches and restore within their damage limit without Argon2 or a password.

## `mhfe password`

Make a password from the [EFF list](https://www.eff.org/dice) of 7,776 words, or from random
characters. The menu offers five random words, five words plus a check word, sixteen characters,
or words chosen with real dice. Enter makes another of the same kind; Escape returns to the menu.
Each replaces the previous password on the private screen.

```bash
mhfe password                   # five random words, about 64.6 bits
mhfe password --check-word      # five random words plus their check word
mhfe password --dice            # five rolls of a six-sided die per word
mhfe password --words 6
mhfe password --chars 16        # about 93.3 bits, without look-alike characters
```

[More password examples](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#6-password) cover
real dice and character counts.

Random choices come from the operating system's cryptographic generator, uniformly. The program
stores no password: write yours down and keep it apart from the container. Where a new container
password is needed, `--new-password own|words|check-word|chars` chooses how to make it in advance.

You can use other text on one line, from 1 to 1,024 bytes after Unicode 18.0.0 NFKD normalization.
Controls, line and paragraph separators, and unassigned characters are refused. Case and spaces
count; lowercase words separated by single spaces are easiest to reproduce.

MHFE warns about passwords estimated below 50 bits, slightly less than four random dice words.
The estimate recognises common passwords, EFF and BIP39 words, years, repeats and keyboard patterns,
but can overrate unfamiliar words or names. Generated passwords have a strength determined by their
random choices.

### A check word

`--check-word` makes five random words and a sixth computed from them. When a six-word password is
typed, MHFE can catch a mismatch before the long computation. Type `?` in place of one forgotten
word; simply leaving it out gives an ordinary five-word password. With one unknown word, MHFE offers
the restoration; when all six words exist but do not fit, it offers six possible repairs. It also
offers lowercase words with single spaces when that form fits.

Nothing changes until you choose it. The password as typed remains an option, since the container
does not record whether its password used a check word. Repairs are offered only on a private
terminal screen. A fitting check word confirms the words belong together, not that they open this
container.

The check word adds no strength to the five words' 64.6 bits and must stay secret: knowing it leaves
about 51.7 bits to guess. If you might disclose a different password of the same container, use
check-word passwords for both so their forms do not distinguish them. The profile is
[MHFE-PASSWORD-CHECK-1](https://github.com/hobby-eng/mhfe-spec#optional-password-check-word-mhfe-password-check-1).

## `mhfe self-test`

```bash
mhfe self-test
mhfe self-test --vectors
```

[More CLI examples](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#7-self-test).

Before a command asks for secrets, its startup self-test compares the cipher, formats, password
rules, repair words, wallet calculations and other components with known answers. It takes about a
third of a second, uses public data and reports nothing when all checks pass. Argon2 is checked at
a small size. A failing component stops the command before its first question.

| Test                       | What it adds                                                                            | Cost                         |
| -------------------------- | --------------------------------------------------------------------------------------- | ---------------------------- |
| Startup, automatic         | Fast known answers and refusal cases                                                    | About 0.3 seconds            |
| `mhfe self-test`           | Slower cases and Argon2 at 64 and 256 MiB                                               | A few seconds, up to 256 MiB |
| `mhfe self-test --vectors` | Encryption of a 24-word container and recovery of a same-length container, at full cost | Roughly 2–4 minutes, 2 GiB   |

The menu asks which of the two requested tests to run. Full-size vectors can find a fault that
appears only with the real Argon2 memory size; the test reports where computation first differed.
`serve` checks only the hashes it uses. Help, version output and `test-benchmark` run no startup
self-test.

If a check fails, do not use that build or computer for a real phrase. Verify the download, try
another computer and report the failure. Warnings and **not available here** describe a missing
protection or check and are distinct from a wrong known answer. Passing tests do not establish
cryptographic security or an unpredictable random generator. The full
[component inventory](https://github.com/hobby-eng/mhfe/blob/main/docs/API.md#self-checks) states what is checked.

## Help

```bash
mhfe --help
mhfe encrypt --help
mhfe --version
```

The [CLI examples](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md#8-help-and-version) cover
short help, detailed help and version output. Run `mhfe --help` for commands and `mhfe <command>
--help` for options. The menu's Help entry shows the same information. [Command-line
reference](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md) covers script input and exit
codes.

## Quit

Choose **Quit**, or press Escape or q at the main menu. From a command, Escape or q at a list and
Ctrl+D at an empty prompt return to the menu; Ctrl+C ends both. A standalone cancelled command ends
with exit code 130.

## Settings: PIM and memory level

Both default to **0**. Keep those defaults unless you have a reason to increase the time or memory
every recovery requires, including your own. `--pim` and `--mem` set them without the questions.

| Memory level      | 0       | 1         | 2       | 3       | 4       | 5        | 6        | … 21  |
| ----------------- | ------- | --------- | ------- | ------- | ------- | -------- | -------- | ----- |
| Memory needed     | 2 GiB   | 3 GiB     | 4 GiB   | 6 GiB   | 8 GiB   | 12 GiB   | 16 GiB   | 3 TiB |
| Recovery at PIM 0 | 1–2 min | 1.5–3 min | 2–4 min | 3–6 min | 4–8 min | 6–12 min | 8–16 min | —     |

These are rough times; encryption with its creation check takes twice as long. PIM ranges from 0 to
1023 and multiplies the time by `PIM + 1`: PIM 1 doubles it; PIM 1023 means roughly 17–34 hours per
recovery at memory level 0. The 64-bit native tool supports all memory levels; the browser supports
level 0 only. MHFE checks native free memory, including Linux cgroup limits, before asking for
secrets at the first settings choice.

**Keep every non-default setting.** The container stores neither PIM nor memory level. Different
values recover a different phrase; forgotten values require full-cost trials over the settings,
with a wallet reference where the phrase cannot check itself. At defaults, the container and
password suffice for recovery; any wallet BIP39 passphrase is still needed to use its funds.

Higher settings multiply an adversary's password-guessing work by a fixed factor. An extra uniformly
random EFF password word multiplies the number of passwords by 7,776; a stronger password usually
helps more.

## In the browser

The browser package runs the same library in an offline page, including encryption, recovery,
checks, rekey, repair and password tools. It loads no remote resources. A host page supplies the
interface; the [browser guide](https://github.com/hobby-eng/mhfe/blob/main/docs/BROWSER-PACKAGE.md) describes the module classes and its duties.

- **Standard mode** works in a page opened as a file. Argon2's four lanes run on one thread;
  recovery takes roughly four to seven minutes.
- **Fast mode** runs those lanes in parallel. `mhfe serve tool.html` serves one local HTML file on
  `127.0.0.1` with the headers the browser requires and opens it. The server receives no secrets;
  the page handles them. `python3 mhfe-fast-mode.py tool.html` from the package's core folder does
  the same with Python 3.8 or later.

Both launchers require a matching `mhfe-fast-mode.sha256` beside the HTML file. Verify the release
too: a checksum stored beside a page alone does not establish its origin. Encryption takes about
twice a recovery in either mode. The [measurement records](https://github.com/hobby-eng/mhfe/blob/main/docs/measurements/README.md) give the
hardware-specific timings.

A browser cannot lock secret memory, control swap or crash reports, or provide a terminal's private
screen. Files from different package builds are refused, and each class checks its components
before use. The package retains a dedicated hidden-wallet session API; it differs from the CLI's
multi-password `decrypt` dialogue. See [Browser security](https://github.com/hobby-eng/mhfe/blob/main/SECURITY.md#the-browser).

<a id="for-scripts"></a>
<a id="for-developers"></a>

## Scripts and development

- [Command-line reference](https://github.com/hobby-eng/mhfe/blob/main/docs/CLI.md): standard input, cancellation, exit codes and download
  checks.
- [Building and checking MHFE](https://github.com/hobby-eng/mhfe/blob/main/docs/DEVELOPMENT.md): source builds, tests, browser checks and code
  layout.
- [Rust and WebAssembly API](https://github.com/hobby-eng/mhfe/blob/main/docs/API.md): operations, data types, outcomes and error codes.
- [Preparing a release](https://github.com/hobby-eng/mhfe/blob/main/docs/RELEASING.md): canonical builds, signatures and publication.

<a id="how-it-works"></a>
<a id="ways-to-use-it"></a>

## Protocol and compatibility

MHFE protects a stored backup, rather than changing the wallet's cryptography. It is intended for
cold storage, not a wallet in daily use. [How it works](https://github.com/hobby-eng/mhfe/blob/main/docs/HOW-IT-WORKS.md) explains the cipher,
recovery checks, hidden wallets, decoys and repair-card limits.

The same phrase, password and settings produce the same container. Make additional copies by
copying those exact words; use a separate password for each original seed phrase. An MHFE password
opens the container. A BIP39 passphrase belongs to the wallet and is neither encrypted nor replaced
by MHFE. Keep each password and passphrase independent of the others.

Version 0.3.0 was the last release with the older protocol format called suite 2. The current
24-word and same-length formats are defined by the
[specification](https://github.com/hobby-eng/mhfe-spec); the current password rules use Unicode
18.0.0. For migration details, see the [0.7.0 notes](https://github.com/hobby-eng/mhfe/blob/main/docs/releases/v0.7.0.md).

## Source and license

The native tool uses RustCrypto's Argon2 through mhfe-core. The browser uses the vendored reference
C implementation, compiled to WebAssembly. Build instructions are in
[Development](https://github.com/hobby-eng/mhfe/blob/main/docs/DEVELOPMENT.md), and [third-party notices](THIRD_PARTY_NOTICES.md) list the
bundled licences. The Rust source is licensed under [MIT](LICENSE).

MHFE was developed with extensive use of ChatGPT and Claude. The retained
[audit reports](https://github.com/hobby-eng/mhfe/blob/main/docs/audits/README.md) document their reviews and checks; these are not independent
cryptographic reviews.
