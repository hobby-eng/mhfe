# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics

[![CI](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml)
[![Release](https://github.com/hobby-eng/mhfe/actions/workflows/release.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/release.yml)
[![Test vectors](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml/badge.svg?event=push)](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml)
[![RustSec audit](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml)
[![Build provenance: GitHub attestations](https://img.shields.io/badge/build%20provenance-GitHub%20attestations-2ea44f)](https://github.com/hobby-eng/mhfe/attestations)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<p align="center">
  <img
    src="assets/mhfe-mascot.png"
    alt="MHFE penguin mascot carrying a cold-storage metal backup"
    width="240"
  >
</p>

<p align="center">
  <sub>The penguin lives in the cold, like the backups MHFE is made for. It holds a
    steel backup with 24 words and waddles from side to side, much as a Feistel network swaps its two
    halves in every round.</sub>
</p>

MHFE turns the seed phrase of a Bitcoin or other BIP39 wallet (12, 15, 18, 21 or 24 English words)
into a password-protected **container of 24 words**. For a phrase of 12 to 21 words you can instead
choose a container **of the same length** as your phrase. The container is itself an ordinary,
valid seed phrase, so it fits the same metal backup or capsule. With the password it turns back into
your exact original seed phrase; without it, getting the phrase back means guessing the password,
which MHFE makes deliberately slow. Your wallet, its addresses and any BIP39 passphrase stay as they
are.

Each recovery deliberately takes about one to two minutes and 2 GiB of memory. You wait once;
someone guessing your password pays that for every guess. An encryption takes twice as long, because
MHFE then recovers your phrase from the new container once to make sure the container works.

This repository is the implementation: a command-line tool, a Rust library and a browser package.
The companion [MHFE specification](https://github.com/hobby-eng/mhfe-spec) defines the algorithm.
This version implements suite `MHFE-BIP39-256-EXPERIMENTAL-3` for 24-word containers and, since
version 0.5.0, suite `MHFE-BIP39-LP-EXPERIMENTAL-4` for containers of the same length.

> **Experimental.** MHFE has not been reviewed by independent cryptographers. Do not use it to
> protect real funds. Keep the backup of your original seed phrase until you have rehearsed a
> recovery.

## How it works

MHFE is made for **cold storage**: a backup of a seed phrase that is written once on paper or a
metal backup, put away, and read again perhaps years later on an offline computer. It is not meant
for a wallet in daily use.

MHFE protects the seed phrase while it is stored and backed up. It does not change the cryptography
of the wallet itself: the keys derived from the phrase are only as safe as the algorithms that use
them, such as the signatures of a coin and the hash functions of its addresses. If one of those is
broken, for example by a quantum computer, the funds can be at risk however well the phrase is
stored.

**Any phrase becomes 24 words.** MHFE accepts a phrase of 12, 15, 18, 21 or 24 words and by default
gives a container of 24 words. Inside, the original seed phrase becomes a 256-bit number that twelve
rounds of a Feistel cipher scramble. Each round derives its key from the password with Argon2id,
using 2 GiB of memory, and needs the result of the previous round, so every guess of the password
costs the full work. The result is written out as 24 words with an ordinary BIP39 checksum: a valid
seed phrase in which nothing shows that MHFE made it. No salt, version or length is stored; with the
default settings, the 24 words and the password are all you need.

**Checksums.** The container's BIP39 checksum catches most mistakes in copying it; one wrong word
slips through in about one case in 256. An original seed phrase of 12 to 21 words leaves room in the
256 bits, and MHFE fills it with a hash of the original seed phrase: the built-in check. On recovery
the built-in check confirms the password and settings and finds the length of the original seed
phrase by itself, so MHFE almost always tells you when the password is wrong. A 24-word original
seed phrase fills all 256 bits and has no built-in check: every password gives some valid phrase,
and only a comparison with the wallet shows whether it is yours.

**12 to 21 words, or 24?** The length is that of your wallet's phrase. If you are creating a new
wallet for cold storage, choose it with this in mind:

| Original seed phrase | On recovery                                                          | Suits                                                                       |
| -------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| 12 to 21 words       | The built-in check confirms the password and finds the length        | Most backups: MHFE tells you when the password or a setting is wrong        |
| 24 words             | No built-in check: a wrong password gives another, equally valid one | Use with an independent BIP39 passphrase, and plausible deniability (below) |

### 24 words or the same length

For a phrase of 12, 15, 18 or 21 words, you can instead choose a container with as many words as the
phrase; 24 words stays the default. The backup then keeps its length and looks like any other phrase
of that length. The choice has costs, so MHFE asks first; the question links here, and `?` there
compares both formats:

| Container             | A wrong password                             | Shows the length of your phrase | A miscopied word slips through                | Tells a guesser the right password       |
| --------------------- | -------------------------------------------- | ------------------------------- | --------------------------------------------- | ---------------------------------------- |
| 24 words (default)    | is detected: MHFE tells you (12 to 21 words) | no, every container has 24      | about once in 256                             | yes, through the built-in check          |
| Same length as phrase | gives another valid phrase, with no error    | yes                             | about once in 16 (12 words) to 128 (21 words) | no, only a wallet's history on the chain |

The same-length container has no room for a built-in check, so only a comparison with your wallet,
with `mhfe check`, confirms a recovery. Like a 24-word original seed phrase, it turns into a valid
phrase with any password. The [specification](https://github.com/hobby-eng/mhfe-spec) defines this
format as suite 4. Its analysis of plausible deniability covers this format too, but its estimates
of what an attack costs are stated for the 24-word format only.

**Convenience or secrecy.** The choice is between a recovery that checks itself and a container that
gives nothing away. The built-in check tells you at once that a password is wrong, but it tells
someone who has the container the same: a guesser recognises the right password when it comes,
although each guess still costs a full recovery. A same-length container, like a 24-word original
seed phrase, gives a valid phrase for every password, so the container alone cannot tell a right
password from a wrong one; this is what makes plausible deniability (below) possible. A guesser can
then recognise the right password only through a wallet with a public history: if the wallet of the
phrase itself, used without a BIP39 passphrase, has ever received funds, the blockchain shows it,
and that confirms a right password just as the built-in check would. Only funds kept under a BIP39
passphrase, while the wallet without the passphrase stays unused, leave no such trace; the password
and the passphrase then have to be guessed together.

**Checking against your wallet.** The built-in check confirms the password but not which wallet the
phrase belongs to, and a 24-word result or a same-length container cannot check itself at all.
`mhfe check` therefore compares a recovery with a receiving address of the wallet or its master key
fingerprint, without showing the phrase (see [Commands](#commands)).

**Plausible deniability.** The container is a valid phrase in its own right, so it can open a small
decoy wallet; that fools only someone who does not know that MHFE was used. A 24-word original seed
phrase offers more: any other password turns the same container into another valid 24-word phrase.
Recover the container once with a decoy password, chosen as randomly as the real one, and use the
wallet it gives as a decoy with a believable balance and history. Under pressure you can hand over
that password; nothing in the container or in what MHFE shows tells it apart from the real one,
because every 24-word result is shown as not verified. The
[specification](https://github.com/hobby-eng/mhfe-spec) analyses this and its limits: it does not
help if the other side knows that your original seed phrase has fewer than 24 words; every copy of
the backup must be an exact copy of the same container; and no other record of the phrase, such as a
paper copy or a hardware wallet, may contradict what you hand over. Like the rest of MHFE, this
analysis has not been independently reviewed.

## Ways to use it

> [!WARNING]
> **The MHFE password is not your BIP39 passphrase!** A BIP39 passphrase, sometimes called the 25th
> word, belongs to the wallet: a wallet asks for it together with the seed phrase, and it stays
> the same after MHFE. The MHFE password only opens the container.
>
> **Every password and passphrase in this tree must be different!** The MHFE password, every other
> MHFE password, every decoy passphrase and the passphrase of each wallet are separate secrets.
> Never use one text twice and never make one from another; whoever found one would then have the
> others.

The same 24 words of the container phrase open different wallets, depending on what is typed with
them. Every branch but the last is optional; the last one leads to your real wallet.

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

**The container as a wallet.** Every wallet accepts the 24 words as an ordinary seed phrase. Leave
that wallet empty, or keep a small amount on it so that the container phrase looks like an ordinary
backup. Anyone who reads the container phrase can spend that amount, and the decoy convinces only
someone who does not know that MHFE was used. Type the container only into a wallet you trust, such
as a hardware wallet: any copy of the container phrase, including the one a wallet stores, lets its
holder try passwords offline.

**A decoy passphrase for the container.** Add a BIP39 passphrase to the container's wallet in
advance and put a believable amount on the wallet it opens. If someone asks for your passphrase, you
can give this one. Whoever has the container phrase and this passphrase can spend that amount, so
keep it to what you can afford to lose.

**Other MHFE passwords: a decoy, or hidden wallets.** Any password other than yours turns the
container into another valid 24-word phrase, and you may use as many such passwords as you like.
[`mhfe wallets`](#mhfe-wallets) shows the wallet each of them opens. Each such wallet serves one of
two purposes:

- A decoy to hand over under pressure, for a 24-word original seed phrase. As described in
  [plausible deniability](#how-it-works), every password gives an equally valid 24-word phrase, so
  the decoy holds even against someone who knows that MHFE was used, as long as the decoy wallet's
  balance and history look like those of a wallet in real use. Choose the decoy password as
  randomly as the real one, and choose no word for the real phrase
  ([a chosen word](#chosen-words) gives it away).
- A hidden wallet behind the one you could disclose, kept secret like your own.
  [`mhfe wallets`](#mhfe-wallets) says how to keep it hidden.

Like any wallet, each of them may have its own BIP39 passphrase, which opens yet another wallet from
the same phrase; it is one more secret, different from all the others. Nothing records which
passwords you used or how many, so you must remember each one. Each of these wallets depends on this
exact container and its settings: `mhfe rekey` or the loss of every copy of the container loses
them, unless their funds were moved first.

**Your original seed phrase.** With your password, MHFE gives back the exact original seed phrase,
and your wallet opens as before. The strongest arrangement is a 24-word original seed phrase with
its own BIP39 passphrase, independent of the MHFE password, while the wallet of the original seed
phrase without a passphrase stays unused. Whoever has the container must then guess the password and
the passphrase together, and the blockchain gives no hint which guess is right. Every secret you add
is one more that you must not forget: a lost passphrase loses the wallet just as a lost password
does.

## Getting started

There is nothing to install. Download the archive for your system from the
[releases page](https://github.com/hobby-eng/mhfe/releases) ([which one](#release-files)), unpack it
and run `mhfe` in a terminal: `mhfe encrypt`, `mhfe decrypt` and the other commands that
`mhfe --help` lists. Started without a command, by a double-click or with the `mhfe-launch` script
in the archive, it shows a menu of the same commands. Each question offers its answers as a list:
choose with the arrow keys and Enter, or press an answer's number; Escape cancels.

Every command that handles a secret first tests every part of the program on this computer, in a
fraction of a second, and stops before its first question if a part gives a wrong answer;
[`mhfe self-test`](#mhfe-self-test) says what it tests.

Use it on a trusted computer that stays offline while the phrase and the password are on it, ideally
a Linux system started from a USB stick with the network off. On Linux MHFE also applies kernel
restrictions against creating sockets and opening files for writing. MHFE confirms each restriction
by trying what it forbids; the command's summary shows which ones took effect and warns when one
that the kernel reported does not hold. Where the system allows it, a command started directly, not
from the start menu, also runs in its own network namespace, with only an inactive loopback and no
external routes. Descriptors already open remain usable, including sockets and redirected output, so
these restrictions do not replace a trusted offline environment. On Windows, Windows PE from a USB
stick is better than your everyday system; `mhfe.exe` needs nothing beyond Windows itself, though it
has not been tested in Windows PE yet.

Swap matters too. The system may write memory to a swap area on a disk, including Argon2's work
area, from which a password guess can be tested cheaply, and the data can stay there for years. On
Linux MHFE therefore warns when a swap area is not encrypted. Use a computer with encrypted swap or
none: a live system started from a USB stick usually has none, macOS encrypts its swap, and on
Windows, use BitLocker or no page file. A command's summary also says whether the secrets you type
are kept in locked memory, out of swap, and warns when the system refused to lock that memory.

## Commands

`mhfe <command> --help` explains every option. Keep a copy of this program offline as well, so that
a compatible version is at hand years from now. While a command runs, its screens keep to short
lines; a grey "More:" line links to the section here that explains them. At a terminal, each step
of a command has a clean screen of its own, and when the command ends the main screen keeps only a
short summary of the answers and results.

Where you type words (a seed phrase, a container phrase, repair words or a password), a grey line
below helps with the word list: after one letter it says how many words begin with it, from two
letters it lists them, and it says so when no word begins like that. Tab completes the word as far
as the words that begin with it agree, and Ctrl+W deletes the last word. For a password the hints
come from the EFF list of dice words, and there Tab stays part of the password. The lists are
public, so the hints tell nothing that someone who sees your screen could not look up; they appear
only where what you type is shown anyway.

Under every seed phrase that mhfe shows, and under a container that it makes or that `mhfe repair`
repairs, a line gives the master key fingerprint: eight hexadecimal digits that wallet apps show to
tell wallets apart (Sparrow calls it "Master fingerprint"). A BIP39 passphrase changes the
fingerprint, so the line says which wallet it is for. In `mhfe new` it is the wallet with your
passphrase. Elsewhere it is the wallet without one: `mhfe decrypt` asks for a passphrase only for
the 16-bit check of a 24-word reading, and `rekey` and `wallets` do not know the passphrase the
wallet is used with. For a wallet with a passphrase, compare the fingerprint your wallet app shows
with `mhfe check --fingerprint`. Under a container, the line gives the fingerprint of the
container's own words, not of your wallet: do not note it as your wallet's. The line appears where
the words appear, never in the summary or in the output for scripts, and not under a container
phrase repaired or found inside another command.

### `mhfe password`

`mhfe password` makes a password of random words from the [EFF dice list](https://www.eff.org/dice)
of 7,776 words: use four, better five. `--dice` uses real dice, and `--words N` sets the count.
`--chars N` makes N random characters instead (16 by default, about 93.3 bits) from 57 letters and
digits without look-alikes such as 0 and O; words are easier to type correctly years later. Random
words and random characters are both drawn from the system's cryptographic random generator, every
one equally likely. The password is shown only once and is not stored: write it down and keep it
apart from the container.

Any text on one line, up to 1,024 bytes after Unicode normalization, can be a password. Control
characters such as a tab, line and paragraph separators, and characters that Unicode 18.0.0 does not
assign are refused. Letter case and spaces count, so lowercase words with single spaces are the
easiest to type again. The password is not your wallet's BIP39 passphrase.

`mhfe encrypt` estimates the strength of the password you type and warns when the estimate is below
about 50 bits, a little under four dice words. The estimate is rough and uses nothing from outside
the program: it knows the words of the EFF and BIP39 lists, common passwords, years, repeats, runs
such as `1234` and keyboard rows such as `qwerty`, also with substitutions such as `0` for `o`. It
can overrate a password made of words it does not know, such as names or words of other languages. A
password from `mhfe password` has a known strength.

From the start menu, the entry first asks which kind to make: five dice words, five words and a
check word, or sixteen random characters. Enter then makes another password of the same kind, and
Escape returns to the menu. Each password replaces the previous one on the private screen, and
leaving that screen clears it.

Where a new container password is set, in `mhfe encrypt`, `mhfe new` and `mhfe rekey`, MHFE first
asks whether you type your own or take one of the same three kinds. A password it makes is shown
once on a private screen. Once you have written it down, you type it back from your copy, so that a
copying mistake shows before anything is encrypted with it; after a wrong copy, MHFE shows the
password again. `--new-password own|words|check-word|chars` answers the question beforehand; a
script always types its own.

#### A check word

`mhfe password --check-word` makes five words and a sixth computed from them, the check word, as the
optional profile
[MHFE-PASSWORD-CHECK-1](https://github.com/hobby-eng/mhfe-spec#optional-password-check-word-mhfe-password-check-1)
of the specification defines it. When you type such a password, mhfe compares its words with the
word list before the long wait:

- If the words fit their check word, the summary says so.
- If one word is misspelt, or forgotten and typed as `?` in its place as the password screen says,
  the check word restores it; mhfe shows the word and asks before using it. A word simply left out
  does not work, since five words are an ordinary password.
- If every word is in the list but they do not fit, one word is wrong and there is no telling which.
  mhfe shows the six possible repairs, one for each place, to compare with what you wrote down.

Letter case and spaces count in such a password as in any other. If its words fit their check word
only when written in lower case with single spaces, mhfe offers that corrected password as well,
also together with a repair.

mhfe never repairs anything without asking and never refuses a password: the container does not
record whether its password has a check word, so the password as typed is always one of the answers.
A check word that fits shows only that the six words belong together, not that the password opens
this container. Type the words in lower case with single spaces, as shown.

The check word adds no strength: the password keeps the 64.6 bits of its five random words. The
check word must stay as secret as the rest, since anyone who learns just the check word has about
51.7 bits left to guess. If you may give away another password of the same container, such as the
password of the main wallet in front of hidden ones, make both with `--check-word` so that they look
alike.

### `mhfe encrypt`

`mhfe encrypt` asks for the phrase and twice for the password, since a mistyped password would lock
the phrase away for good. Both are typed on a private screen that shows what you type and is cleared
as soon as you are done. The words of the seed phrase may be typed in any case or as their first
four letters, and the word list or the checksum refuses a mistyped word; the password must be typed
exactly, letter case and spaces included. For a phrase of 12 to 21 words, MHFE next asks how long
the container should be: 24 words, the recommended default, or the same length as your phrase. `?`
explains both, and `--same-length` chooses the same length without asking. After the encryption,
MHFE shows the container's format, the suite identifier.

The container appears after one to two minutes, on a private screen like the phrase. Write it down
while MHFE checks it by recovering your phrase from it, and rely on it only once MHFE says
"Verified". Enter or Escape then clears that screen, so that the container leaves no copy in the
terminal's history; press either key only once you have written the words down and checked them.
With the default settings, the container's words and the password are all MHFE needs; in the rare
case that MHFE asks you to note the word count, do so. The same phrase, password and settings always
give the same container. A lost container phrase can therefore be made again, and two identical
containers reveal the same phrase: use a different password for each phrase.

After the encryption, MHFE lists what to keep: the container's words, the password and any BIP39
passphrase of the wallet, and, only where needed, the repair words, changed settings or the word
count. MHFE encrypts the phrase, not the passphrase, so a wallet with a passphrase still needs it.
The list always names the passphrase, but MHFE neither asks whether there is one nor asks for it.
Use the password for this phrase and nowhere else, and make another copy of the container only by
copying its words exactly.

Before you rely on the container, rehearse the recovery with `mhfe check`, typing the words of the
container phrase as you wrote them down, not from the screen, and keep the backup of your original
seed phrase until the check matches. This matters most for a container of the same length: its
shorter checksum lets a miscopied word through more often, and the container then opens another
wallet without any error.

### `mhfe check`

`mhfe check` rehearses a recovery before you rely on a container. It shows only "matches" or "does
not match", never the phrase; for a matched address it also shows where it was found, such as
`m/84'/0'/0'/0/5`. At a terminal, a match lists each check that passed: the container phrase's BIP39
checksum, the container's own wallet when a search found missing words with it, the reference it was
compared with, and those of the original seed phrase's own checks that the same recovery passes, its
built-in check or the 16-bit phrase + passphrase check.

Type the container phrase as you wrote it down, not from the screen. One miscopied word passes the
BIP39 checksum in one case in 256, or as often as one in 16 for a 12-word container of the same
length; for a 24-word original seed phrase or a same-length container, the recovery then silently
gives another wallet. A same-length container has no built-in check, so compare it with your wallet.

Compare with a receiving address of the wallet, the strong check that also covers a BIP39
passphrase, or with the master key fingerprint, a quick check of only 32 bits. The address may be
one of twelve coins: Bitcoin, Ethereum and every EVM network (BNB Smart Chain, Polygon, Avalanche
C-Chain, Arbitrum, Optimism, Base and others), XRP, Tron, Zcash (transparent addresses), Dogecoin,
Bitcoin Cash, Litecoin, Ethereum Classic, Cosmos, Injective and Dash, both Dash Core `X…` and Dash
Platform payment `dash1k…` addresses (DIP17, on `m/9'/5'/17'/account'/0'-1'/index`). MHFE refuses
shielded addresses of Zcash (`zs1…`, `u1…`) and Dash (Orchard, `dash1z…`) and says why: their keys
need their own cryptography. Use the same wallet's transparent `t1…` or Dash `X…` or `dash1k…`
address instead. MHFE asks for the coin, or takes it from `--coin`; a script without `--coin`
compares with a Bitcoin address and says so ([For scripts](#for-scripts)). Before the check, MHFE
shows what it searches: the first 100 receiving and change addresses of accounts 0 to 9 on the
standard paths of that address, or one path with `--path`. Do not keep the address or fingerprint
next to the container.

For a phrase drawn so that its BIP39 seed passes a check, as `mhfe new` does on request and other
programs following the specification can, the list of what to compare with also offers "The phrase +
passphrase check" for a 24-word container. This is a 16-bit hash of the seed, which BIP39 derives
from the phrase and the passphrase together. The check asks for the BIP39 passphrase, which may not
be empty, compares only the container's 24-word reading, and confirms the password and passphrase,
not the wallet.

"The container's built-in check" is the check of a 12- to 21-word original seed phrase in a 24-word
container. With it, the question about the length offers "Detect automatically" last, as
`--words auto` does. MHFE then takes the length whose built-in check passes and asks whether a BIP39
passphrase is used with the original seed phrase; with that passphrase, detection also finds a
24-word phrase drawn with the phrase + passphrase check. When no length is found, MHFE asks how many
words the original seed phrase has. A 12- to 21-word length then does not match, since detection
already tried it; for 24 words, MHFE compares a receiving address or the fingerprint with the same
recovery, without running the rounds again. With a length stated, a built-in check that passes at
another length takes precedence: the check matches, and MHFE says which length it found.

When it does not match, the check cannot tell what is wrong: the password, a setting, the container,
the BIP39 passphrase or the reference. Without an address or fingerprint, for a 12- to 21-word
original seed phrase in a 24-word container, it uses the container's built-in check, which proves
the password and settings but not the wallet or its passphrase.

### `mhfe decrypt`

`mhfe decrypt` gives back the original seed phrase. The container is typed on a private screen,
which shows it as you type it; the phrase then appears on a private screen as well, which Enter or
Escape clears once you have written it down. Neither stays in the terminal's history. The number of
words tells MHFE the format: 24 words is the default format, 12 to 21 words a container of the same
length. The summary shows the container's format.

For a 12- to 21-word original seed phrase in a 24-word container, MHFE confirms the password and
finds the length itself; a wrong password then shows as "Not verified". A 24-word original seed
phrase and a same-length container have no such check: a wrong password gives another valid phrase,
so compare the result with your wallet.

A new 24-word phrase can be made with a 16-bit check of its own, tied to its BIP39 passphrase, as
`mhfe new` offers. The container does not show whether a phrase was made with it, so MHFE tests
every 24-word reading. When one comes out, MHFE asks whether a BIP39 passphrase is used with the
phrase, says why, and tests the reading with that passphrase or with none. It then says whether the
reading passes the 16-bit check. A pass makes a right password very likely but does not show which
wallet it is. A failure matters only if your wallet was made with the check, since a phrase made
without the check fails it. A script gets the test without a passphrase, unless it gives
`--passphrase-used yes` and the passphrase on the line after the password (the third line, or the
fourth with `--repair`); that line is read only when a 24-word reading comes out.
`--passphrase-used yes|no` also answers the question at a terminal.

`--words N` states the length of the original seed phrase; MHFE then accepts only a 24-word
container or a same-length container of exactly N words. A stated length does not replace detection,
because a check that passes is far more reliable than memory. When the built-in check of another
length passes, MHFE takes that length and tells you. When no length passes and you stated 12 to 21
words, the password or a setting is probably wrong, or the phrase has 24 words. When you state 24
words but a shorter length passes, MHFE shows the shorter reading first and the 24-word reading
after it; a receiving address of your wallet tells them apart. For about one container in four
billion, several lengths pass their check by accident; MHFE then shows each reading, and you compare
them with your wallet or choose the length with `--words N`.

### `mhfe rekey`

`mhfe rekey` puts the same seed phrase into a new container, under a new password, new settings or
both. It asks for the old container, its password and settings, and, for a 24-word container, the
length of your phrase. Before it encrypts anything again, it confirms the recovery.

A 12- to 21-word phrase in a 24-word container passes its built-in check at that length, with
nothing to choose. If the check finds a length other than the one you gave, MHFE tells you and asks
for a receiving address or the master key fingerprint of your wallet, or shows you the phrase. When
you gave 24 words and a shorter length passes, only an address or the fingerprint, compared with
both readings, can confirm the recovery.

A 24-word phrase or a container of the same length has no such check, so a list asks how to confirm
the recovery: by a receiving address or the master key fingerprint of your wallet, as `mhfe check`
compares them, or, if you know neither, by "I know neither: show me the phrase". That answer shows
the phrase on a private screen, to compare word for word with an independent written record of it,
such as the backup of your original seed phrase, or to enter into your wallet and see your
addresses. From memory such a comparison confirms little. Nothing goes on until you answer yes or
no, and a key pressed before the question appears does not count.

For a 24-word phrase or a same-length container, MHFE then gives the master key fingerprint of the
confirmed phrase, with your passphrase if the wallet has one, so that you can rehearse the new
container with `mhfe check --fingerprint`. A 24-word reading is also tested with the 16-bit check,
as `mhfe decrypt` does, with the passphrase typed for an address or the fingerprint, or with none;
the summary says when it passes, but that check never confirms the phrase on its own. Encrypting
under the old password and comparing would prove nothing, so MHFE does not offer that.

The question about the length offers "Detect automatically" last, as `--words auto` does. Whatever
length is found, the list then asks how to confirm the phrase, as for 24 words: a 24-word phrase can
pass a shorter phrase's check by chance, and trusting the check alone would then encrypt the wrong
wallet again. A given address or fingerprint is compared with every reading. For about one container
in four billion, several lengths pass their check by accident, and the built-in check cannot tell
them apart, even with the length you gave. MHFE then asks for a receiving address or the master key
fingerprint, which tells the readings apart, or asks the length and shows you that reading to
compare with your backup. The old container is recovered once: a second way to confirm the recovery
does not repeat the wait.

Whichever way confirms the recovery, MHFE asks once whether the wallet has a BIP39 passphrase, so
that the list of what to keep names it. The question comes before any address or fingerprint is
typed, because an address or fingerprint compared without a passphrase matches only the wallet of
the phrase alone, which says nothing about funds kept under a passphrase. Neither answer is marked
at first, so that a hurried Enter cannot leave the passphrase off that list: the hint below the
answers says "Enter selects once one is marked", and Enter does nothing until an arrow key has
marked an answer, while 1 or 2 chooses at once. Where the answers come as a numbered list instead,
the prompt `Choice:` has no default: type the number, as an empty line is refused.
`--passphrase-used yes|no` answers the question beforehand, and
`--confirm check|address|fingerprint|show` answers how to confirm the recovery.

After an address or the fingerprint, MHFE asks for the passphrase only if the wallet has one, and
refuses an empty one, since you said there is one. All of this comes before the long work starts.
Then MHFE asks for the new settings and password and makes the new container as `mhfe encrypt` does,
in the same format as the old one.

The old container is not revoked: with the old password it still opens your wallet. Rehearse the new
container phrase with `mhfe check`, preferably on another day. Whether you keep the old one is your
choice; while you keep both, two containers of the same phrase exist, which plausible deniability
does not cover.

Wallets that other passwords open on the old container, such as a decoy, do not move to the new one:
on the new container, those passwords open different wallets with new addresses. Your own wallet
keeps its addresses. Before the container phrase is typed, MHFE tells every user that the wallets of
other passwords do not move and says to keep the old container, its passwords, and a PIM or memory
level that is not 0, until you have moved the funds of those wallets. It asks nothing about such
wallets, since an answer would be a record of one. The result says once more that the old container
phrase still opens the wallet with the old password.

MHFE shows the phrase for the comparison only on a private screen. Where none can be opened, such as
when the output goes to a file, it does not offer that choice.

### `mhfe new`

`mhfe new` generates a new 24-word wallet and its container in one go. It draws the phrase from the
operating system's random generator, shows it once on a private screen for your wallet, and
encrypts it under your password as `mhfe encrypt` does. Where no private screen can be opened, such
as when the output goes to a file or to another terminal, it refuses to start.

It asks for the BIP39 passphrase of the new wallet, if it is to have one. Only with a passphrase
does it then ask whether you want a check that confirms the password at recovery, with nothing
preselected:

- **No check**, the usual case for a 24-word phrase and the only one without a passphrase. Every
  password gives an equally valid wallet, so a decoy password keeps working, and a recovery cannot
  tell a wrong password: confirm it with an address or the fingerprint.
- **A phrase + passphrase check**, for funds kept under the passphrase. The phrase is drawn so that
  a tagged SHA-256 of its BIP39 seed, made with the passphrase, starts with 16 zero bits; the exact
  bytes are in [docs/API.md](docs/API.md). `mhfe check` with the passphrase then says whether a
  recovery passes. A wrong password or passphrase still slips through once in about 65,536, so a
  pass is strong evidence, not proof, and only an address or the fingerprint shows which wallet it
  is. A guess of the password can be tested only together with a guess of the passphrase. Drawing
  the phrase this way leaves about 240 of its 256 bits, still far beyond any search.

The check has costs:

- Keep all funds in the wallet the passphrase opens. The wallet of the phrase alone stays empty and
  is never used: its public history would let an attacker confirm the MHFE password on its own, and
  the searches for the password and the passphrase would add up instead of multiplying. The check
  is only as strong as the passphrase, and MHFE warns about a weak one.
- The passphrase is fixed when the wallet is made. Another one fails the check, except by chance
  or when someone searches for one that passes, which takes about 65,536 tries; a decoy MHFE
  password passes only after about 65,536 recoveries.
- A phrase that passes is statistical evidence that it was made this way, since a random one
  passes once in about 65,536.
- The specification's deniability results assume a uniformly random phrase and do not by
  themselves cover a phrase drawn to pass the check.
- It is for new wallets only. The check is the draft profile MHFE-WALLET-CHECK-SEED-1, which the
  specification defines as an
  [optional source profile](https://github.com/hobby-eng/mhfe-spec#optional-source-profile-a-recovery-check-for-new-24-word-phrases)
  and which is still experimental. Keep a copy of this program with the container.

#### Chosen words

Then `mhfe new` asks whether you want to choose a word of the new phrase. We advise against it; the
reason is below. You may choose one word, typed on the private screen, for a position from 1 to 24
or for anywhere in the phrase. You may also name one word the phrase must never hold, or give it
with `--never-use`. MHFE draws phrases until one meets both wishes, so every phrase that meets them
is equally likely.

Before it draws, MHFE says how many of the 256 random bits remain for someone who knows the word:

- A word at a fixed position takes 11 bits, one anywhere about 6.4, the word never to use about
  0.02.
- At 240 bits or more, which is what the check alone leaves, the phrase still has far more than
  enough.
- Below 240 it is allowed but not recommended. A word at a fixed position, a word never to use and
  the check leave 228.98 bits, the least these wishes can leave, or 244.98 without the check.

A chosen word costs more than these bits once someone learns or guesses it: it lets them rule out
almost every wrong password and tell this wallet from a decoy. Never tell anyone your chosen word.
Choose no word for a wallet you would protect with a decoy; MHFE says so before it draws. A word
never to use, on its own, tells too little to matter.

For example, someone who has a copy of your container tries passwords on their own computer.
Normally, every wrong password turns a 24-word container into another valid 24-word phrase, so the
phrase itself never tells them whether a guess was right: they can only check each result against
the blockchain, and a decoy wallet looks as genuine as the real one. Now suppose they know, or
guess, that you put "zoo" first. They look at each decrypted phrase: a wrong password gives "zoo"
in first place only about once in 2,048 tries, so they need to check only those few phrases against
the blockchain, and your BIP39 passphrase no longer multiplies their work as fully as it would. A
decoy wallet almost always gives itself away: "zoo" is not in first place. All this works only if
they know or guess the word; if nobody knows or can guess it, the phrase stays as strong as a
random one. The random bits MHFE states are the worst case, for someone who knows the word. But a
word people choose themselves often means something to them and can be learned or guessed. This is
why we advise against this mode.

Why only advise against it? One known word filters out about 2,047 of 2,048 wrong passwords. The
rest must still be checked against the blockchain, and a strong BIP39 passphrase still multiplies
the work, though about 2,048 times less than without a chosen word. Only then does the phrase lose
11 of its 256 bits. A decoy is another matter: someone who knows the word tells it apart about
2,047 times in 2,048.

The opposite use is possible too: with a hidden wallet behind an honest disclosure, a word you are
known to like, placed in the wallet you would disclose, is one more sign that this is your real
wallet; the hidden wallets are random phrases anyway. The wallet's own history remains the main
evidence.

A word chosen anywhere in the phrase tells less: a random phrase holds a given word somewhere about
once in 85. Other programs may let you choose a word of a shorter phrase. In a 24-word container
such a phrase has its built-in check already, so a chosen word costs only randomness there. In a
container of the same length there is none: one known word works as a check of the password, which
about one random phrase in 2,048 passes, and unmasks a decoy in the same way.

The chosen word is part of the secret phrase: MHFE never shows it outside the private screen, and
the summary says only whether there was one. Such a phrase is equally likely among the phrases that
meet the wishes, not among all phrases; the specification's results assume a uniformly random
phrase. Choosing a word is a feature of this program, not part of the specification.

### `mhfe wallets`

Every password other than the container's own opens another valid 24-word wallet on a 24-word
container. `mhfe wallets` shows the wallet each password you type opens, so that one container can
carry hidden wallets behind the one you could disclose: under pressure you give the container's own
password, and the wallet it opens, with its genuine history, is all anyone sees. The specification
describes this as a hidden wallet behind an honest disclosure.

Nothing is created or stored: the container and a password give the same wallet every time, so a
wallet need not be written down, and nothing records which passwords you used or how many. A hidden
wallet exists only as the output of the program, and any correct program must find it again later,
so run `mhfe self-test --vectors` once on the computer before you fund one. All wallets appear,
together with their passwords, on one private screen that is cleared at the end, so the main screen
shows neither the wallets nor how many you opened; without a private screen the command refuses to
start. A password whose wallet passes the built-in check of a shorter phrase, as the container's
own password of a 12- to 21-word phrase does, is refused, so that recovery never calls a hidden
wallet verified. So is one whose wallet passes the phrase + passphrase check of a new phrase, with
the main wallet's passphrase or without one.

To keep a hidden wallet hidden:

- Fund it only from sources linked neither to you nor to the main wallet. Moving money from the
  main wallet to it links the two.
- Give each a strong password of its own, different from the container's own and from the others.
- Keep no watch-only copy of it on an everyday device: such a copy is evidence of it.

A hidden wallet depends on the exact container and settings. `mhfe rekey`, another suite, a
forgotten password or the loss of every copy of the container loses it, unless its funds were moved
first. Hidden wallets have 24 words for now.

### `mhfe repair`

A written container phrase can fade, rust, be scratched or be copied with a wrong word. Repair words
are a few extra words, kept on a card apart from the container phrase, with which MHFE repairs the
container phrase without the password: each repair word repairs one word that cannot be read, and
two repair one word that is wrong. When you make a container with `mhfe encrypt`, `mhfe new` or
`mhfe rekey`, MHFE asks whether you want them and recommends four; `--repair-words N` answers
beforehand, 0 for none:

| Repair words | Unreadable words repaired | Or wrong words repaired |
| ------------ | ------------------------- | ----------------------- |
| 2            | 2                         | 1                       |
| 4            | 4                         | 2                       |
| 6            | 6                         | 3                       |
| 8            | 8                         | 4                       |

They appear under the container once its check has passed, as a card to write down: the name of
the profile, MHFE-REPAIR-1, and the words numbered as `1/4` to `4/4`. The summary adds the card to
what to keep. A new password or new settings give a new container, which needs a new card. For a
container you already have, `mhfe repair-words` makes them; the start menu has one entry for both
commands.

You need not run `mhfe repair` first. `mhfe decrypt`, `mhfe check`, `mhfe rekey` and `mhfe wallets`
take `?` in the container phrase too and then ask at once for the repair words. Without them,
Enter alone there offers a search for the words typed as `?`, which [Can MHFE find a missing word
without the repair words?](#can-mhfe-find-a-missing-word-without-the-repair-words) describes; its
last answer lets you type the container phrase again. When the words are not a valid container,
from a typing mistake or a miscopied word, MHFE says so and asks whether to type them again or
repair them with the card; Enter alone at the repair words then lets you type the container phrase
again. The repaired container phrase is shown with every word that was repaired, and used only
after "Use it"; the summary records which words were repaired, never the words themselves.
`--repair` asks for the repair words right after the container phrase, at a terminal and in a
script alike.

`mhfe repair` repairs a container phrase: type its words with `?` for each word you cannot read,
then the repair words, with `?` where needed too; the card can be typed as written, with its name
and numbers. A word that is not in the BIP39 list counts as unreadable, and four letters of a word
are enough. It shows the repaired container and every word it repaired with what was read there,
never repairing silently; correct your written container phrase with them and rehearse with
`mhfe check`. MHFE rejects a repair when it detects a decoding failure or an invalid BIP39
checksum. Damage beyond what the repair words can repair, or a card from another container phrase,
can instead give a wrong result that passes the checksum, and the program cannot always recognise
this. A successful repair therefore does not confirm the intended wallet.

Without the card, Enter alone at a terminal offers the same search for words typed as `?` as the
other commands: by the container's own wallet without the password, or, with the password, by your
wallet or the original seed phrase's own checks. The container's settings are asked once such a
search is chosen, or given with `--pim` and `--mem`, and `--scan-gap` sets the addresses a search
for two words covers.

Keep the card apart from the container phrase, so that one accident or one thief does not take
both. Guard it like the container phrase: a container is what someone needs to try passwords, and
whoever finds the card together with a damaged or partial copy of the container phrase can repair
that copy as you can. The card alone also reduces the number of possible containers: in the
idealized checksum model, eight repair words leave roughly `2^168` checksum-valid candidates for a
24-word container, but roughly `2^40` for a 12-word container. These counts neither identify the
true container nor bypass its MHFE password, but the card is still a partial copy and needs the
same protection. The repair words use the optional Reed–Solomon profile
[MHFE-REPAIR-1](https://github.com/hobby-eng/mhfe-spec#optional-repair-words-mhfe-repair-1) of the
specification; [`src/repair.rs`](src/repair.rs) describes it byte for byte.

### `mhfe self-test`

**At every start.** Before a command that handles a secret asks for anything, MHFE tests itself on
this computer: `new`, `encrypt`, `decrypt`, `check`, `rekey`, `wallets`, `repair`, `repair-words`
and `password` do so, and the start menu does it once before it opens. Every part of the program is
compared with known answers, taken from published test vectors or from an independent program that
first reproduced a published one, and each check is also given something it must refuse, such as a
wrong repair card, a wrong check word or a damaged address. The parts are the hash functions,
Argon2id with a small amount of memory, the twelve rounds of the cipher in both directions, the
formats and the length detection, the password rules, the word list, repair words, the search for
missing words, the check word, the password generator and the test that refuses a broken random
generator, wallet keys and addresses, the paths an address check says it will search, the wallet
check, hidden wallets, rekey, the rehearsal check, the hints of the word lists, the chosen word of a
new phrase and the list of what to keep. The rounds are replayed with the keys that the published
MHFE vectors record, so this does not need 2 GiB of memory. The command also reads back whether
core dumps are off, which of the kernel's restrictions hold and whether memory can be locked. All
of this takes a few hundredths of a second, uses public test data only and shows nothing when every
part passes.

If a part gives another answer, the command stops before its first question, with exit code 1:

```text
✗ Error: Self-test at start failed: Cipher rounds: vector 5 of 10 gives other
         repair words. Do not use this program on this computer.
  More: https://github.com/hobby-eng/mhfe#mhfe-self-test
```

A broken build, a faulty processor or memory, or a damaged download that changes one of these
answers then shows before you type a secret, not years later in a container that does not open.
Damage to a part of the program that no test reaches can go unseen, so check every download against
its `SHA256SUMS` ([Release files](#release-files)) all the same. When a test fails, do not use that
program or that computer for a real phrase: check the download, try another computer, and report
it. "Core dumps could not be turned off." stops a command in the same way: the system kept them on,
so a crash could write your secrets to a disk.

`mhfe serve`, which handles no secret, tests only the hashes, SHA-256 among them, before it compares
a page with its checksum. `mhfe self-test` runs these tests itself and shows each one. The test
tools `mhfe test-vectors` and `mhfe test-benchmark`, which handle public test data only, and
`--help`, `mhfe help` and `--version` run no test at start.

**On request.** `mhfe self-test` runs every test of the start together with slower ones, in a few
seconds and with about 256 MiB of memory: Argon2id also at 64 and 256 MiB, all 27 published MHFE
vectors instead of 10, more cases of the formats, the word list, repair words, the wallet check,
seeds and addresses, every Unicode character against the rule that refuses control characters and
line separators in a password, with a check that normalization turns no other character into one,
and 1,024 bytes of the system's random generator. It also tests that the terminal turns its own echo
off, as every question for a secret needs; such a question itself refuses to read when the echo
stays on: "The terminal did not turn its echo off; no secret was read." It shows one line for each
part: "as published", or for the protections and the generator "off", "enforced", "echo off",
"works" or "healthy". A part that cannot be tested here says "not available here" and why, and a
yellow "!" marks a protection weaker than it should be; neither is a failure. The test ends with
"✓ Every part of this program gives its known answers." and exit code 0, or with "A part of this
program does NOT give its known answers." and exit code 1.

**With the published vectors.** `mhfe self-test --vectors` then also encrypts the public suite 3
vector zero-12 and recovers the public suite 4 vector same-length-zero-12 at their full cost,
2 GiB and 12 rounds each, about two to four minutes, and compares the results with the published
ones. A fault that appears only at Argon2's full size shows in this test alone; an encryption
would not notice it either, since it would encrypt and check in the same wrong way. When a result
is not as published, it says where the work first left the published path. If, in the first round
that went wrong, Argon2id was given an input, password or salt, that the published vector does not
have, the fault lies before Argon2id: in that round's password or salt, or in what the round
started from. If Argon2id was given the published input there and returned another key, the fault
lies in Argon2id. When every Argon2id input and key is as published, the fault lies after the last
Argon2id call of the encryption or the recovery. Run it once before you trust a computer with a
real phrase, and before you fund a hidden wallet. The start menu's entry asks which of the two
tests to run.

No test can show that a random generator is unpredictable: these find one that is stuck or plainly
broken, not one that only looks random. If any test fails, do not use that program or computer for
a real phrase, and report it.

## Settings: PIM and memory level

Both default to 0, and most people should leave them there. At a terminal, each command offers the
defaults first and lets you choose your own instead; `--pim` and `--mem` give them on the command
line. Raising them makes every recovery, yours included, slower or more memory-hungry:

| Memory level (`--mem`) | 0     | 1     | 2     | 3     | 4     | 5      | 6      | ... 21 |
| ---------------------- | ----- | ----- | ----- | ----- | ----- | ------ | ------ | ------ |
| Memory needed          | 2 GiB | 3 GiB | 4 GiB | 6 GiB | 8 GiB | 12 GiB | 16 GiB | 3 TiB  |
| Recovery at PIM 0, min | 1–2   | 1.5–3 | 2–4   | 3–6   | 4–8   | 6–12   | 8–16   | ...    |

An encryption takes twice these times. The PIM (`--pim`, 0 to 1023) multiplies the time: PIM 1
doubles it, and at PIM 1023 a recovery takes roughly 17 to 34 hours. The computer that recovers the
container must have the memory of the chosen level. MHFE checks this before it asks for anything,
and on Linux also checks the memory limit of a container or a systemd unit it runs in. The
command-line tool, which needs a 64-bit system, supports every level; a browser supports memory
level 0 only. A higher setting raises an attacker's work by a fixed factor, while each extra random
password word multiplies it by 7,776, so a better password is worth more than a higher setting.

> [!WARNING]
> **Changed the PIM or the memory level? Remember the values!** With the defaults, both 0, the 24
> words and the password are all you need. A container made with other values opens only with
> exactly those values; with any others it turns into a different phrase that looks just as valid,
> and nothing in the container tells which values were used. A forgotten value then has to be found
> by trying one value after another (PIM 0 to 1023, memory level 0 to 21). Each try is a full
> recovery that takes longer the higher the value, and for a 24-word original seed phrase each
> result must also be compared with your wallet.

## In the browser

The browser package in `dist/` (see [`docs/BROWSER-PACKAGE.md`](docs/BROWSER-PACKAGE.md)) runs the
same code in a web page, for example in the offline wallet tools. It offers everything the
command-line tool does except what only an operating system or a terminal can give, such as memory
levels above 0. It is a set of module classes, each usable alone, over one shared WebAssembly: the
encryption core, repair words, the password tools and the wallet tools. Encryption and recovery
have two modes:

- **Standard mode** works everywhere, even in a page opened as a file. Argon2 runs on one thread, so
  a recovery takes about four to seven minutes, and an encryption about twice that.
- **Fast mode** runs the four Argon2 lanes in parallel, about a quarter slower than the command-line
  tool. A browser allows this only on a page served with particular headers. `mhfe serve tool.html`
  serves one HTML file from this computer (127.0.0.1) with those headers and opens it in the
  browser. `mhfe serve` sees none of your secrets: all the work happens in the page. When a tool
  and its checksum file lie next to the program, the first entry of the program's start menu,
  already marked when the menu opens, serves that tool, so a double-click and Enter are enough. On
  a computer with Python 3.8 or later but without the mhfe program,
  `python3 mhfe-fast-mode.py tool.html` from the browser package's core does the same. Both serve a
  page only when its checksum file `mhfe-fast-mode.sha256` lies next to it and matches.

The package never connects to anything: it loads no remote resources.

Before its first use, each module of the package tests its parts as the command-line tool does at
start, and refuses to work if one fails. A page can also run the longer test and, on request, the
published vectors. The longer test names what a browser cannot test, such as core dumps or locked
memory, with the reason. Files of different builds of the package are refused before they work
together, even when only one script differs. An Argon2 build that the browser does not start gave
no wrong answer, so it counts as no failure: the test says why Argon2 is not available or, when only
the fast mode's build does not start, that it tested the standard mode's build instead.

Both kinds of container work in the browser too: a page asks for the same length with
`sameLength: true` in its `encrypt` call, and recovery takes either kind.

## For scripts

`--stdin` reads the answers from standard input, one per line, instead of asking:

- `encrypt`: the phrase, the password, and the password again. The container has 24 words unless
  `--same-length` is given, and with `--repair-words N` its repair words follow it on a second line
  of the output. As at a terminal, the list of what to keep names any BIP39 passphrase of the
  wallet.
- `decrypt`: the container and the password. With `--passphrase-used yes`, the BIP39 passphrase of
  the original seed phrase follows on the next line, for the 16-bit check; it is read only when a
  24-word reading comes out. With `--repair`, the repair words follow the container on their own
  line, `?` marking unreadable words in either, and the repair is reported on standard error.
  `check` takes `--repair` the same way.
- `check`: the container and the password, then with `--address` or `--fingerprint` the reference
  and the BIP39 passphrase (an empty line if the wallet has none); with `--words N` nothing more,
  and with `--words auto` the BIP39 passphrase of the original seed phrase (an empty line if none).
  `check --stdin` needs one of these three options, because it cannot ask which reference to use.
  Nor can it ask for the coin: `--address` without `--coin` means a Bitcoin address, as in earlier
  versions. The summary then says "Bitcoin, as no --coin was given", and an address that is not
  Bitcoin's is refused with a message that names Bitcoin and `--coin`. For an address of another
  coin, give `--coin`, such as `--coin ethereum`.
- `repair`: the container phrase, then the repair words, `?` marking a word that cannot be read in
  either. The output is the repaired container on one line, or nothing when there is nothing to
  repair.
- `repair-words`, which needs `--count N`: the container. The output is the repair words on one
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
| 130  | Cancelled: Ctrl+C, Escape or q at a list, Ctrl+D at a secret's prompt, SIGTERM or a closed terminal |

A command is cancelled with Ctrl+C at any moment, with Escape or q at a list of answers, and with
Ctrl+D at the empty prompt of a secret. Ctrl+C stops the tool at once, even in the middle of a
round; the operating system then discards its memory. SIGTERM and a closed terminal end it in the
same way at any moment, and Ctrl+\ and Ctrl+Z do so while it works; at a question they are ordinary
keys. Each of them first restores the terminal and leaves the private screen.

## Release files

A release has archives for Linux (x86-64 and ARM64), macOS (Intel and Apple silicon) and Windows
(x86-64), each with the `mhfe` program, its launcher and the licences. It also has the browser
package. A single x86-64 program runs on every 64-bit x86 processor: it uses SSSE3 where the
processor has it, 7 to 10% faster ([measured](docs/measurements/README.md)), and SSE2 otherwise.

Check a download against the release's `SHA256SUMS` before you use it and, from v0.5.0 on, check
the OpenPGP signature of that file too: import `RELEASE-SIGNING-KEY.asc` from the release, compare
its fingerprint with `28FC51B1DB80DF2101128CB30EDD4814591DD095`, as given in
[docs/RELEASING.md](docs/RELEASING.md) and at `https://github.com/hobby-eng.gpg`, then run:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

Every release file also has a signed build provenance: GitHub records which run of the release
workflow built it, from which commit. Check it on the computer you downloaded the file with, since
the check needs the network, and only then carry the file to the offline computer:

```bash
gh attestation verify mhfe-v0.6.0-linux-x86_64.tar.gz --repo hobby-eng/mhfe
```

The provenance of v0.3.0 to v0.5.0 names commits from before a rewrite of this repository's
history; [docs/releases/history-rewrite-2026-10-09.md](docs/releases/history-rewrite-2026-10-09.md)
pairs each with the commit its tag names now.

## For developers

To build from source, install Rust and run `cargo build --release --locked`; the program is then
`target/release/mhfe`. Release builds and the scripts below replace the builder's own paths in the
program and the WebAssembly (`packaging/remap-builder-paths.sh`), so they refuse `RUSTFLAGS` and
`CARGO_ENCODED_RUSTFLAGS`. Give extra flags per target instead, such as
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS`.

```bash
cargo test --locked          # fast tests with reduced Argon2 cost
scripts/check.sh             # lints, tests, builds, browser package; not the full-size vectors
dprint check                 # dprint 0.63.0: Markdown, JSON, TOML and YAML (dprint.json)
# After check.sh: the browser package in the pinned Chrome and Firefox, unpacked in DIR as
# .github/actions/browser-checks does (the versions are in xtask/src/browser.rs).
MHFE_BROWSERS=DIR cargo xtask package-check
MHFE_BROWSERS=DIR cargo xtask browsers
# The published vectors at full size: about an hour for suite 3, half an hour for suite 4.
cargo test --locked --release --test suite3_vectors -- --ignored --nocapture
cargo test --locked --release --test suite4_vectors -- --ignored --nocapture
scripts/build-reproducible.sh
```

The library API is in [`docs/API.md`](docs/API.md) and the security notes in
[`SECURITY.md`](SECURITY.md). [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) has the licences of
the bundled Argon2 code, EFF word list, browser JavaScript runtime and Rust crates; its crate list
is written by `scripts/third-party-licenses.py`, and every release archive carries the file. Timing
records are in [`docs/measurements/`](docs/measurements/).

Test vectors are written with `mhfe test-vectors` (`--same-length` for the suite 4 set in
`tests/fixtures/suite4-vectors`) and checked independently with `scripts/independent-suite3.py`
and `scripts/independent-suite4.py`, which use OpenSSL's Argon2 and the Unicode 18.0.0 database of
`unicodedata2`. Their packages install with
`python3 -m pip install --require-hashes -r scripts/independent-suite3-requirements.txt`, and
`python3 scripts/independent-suite3.py passwords tests/fixtures/validation-cases.json` checks the
password rule on every case of the specification.

The tests at start replay the published vectors from `src/mhfe/published_rounds.rs`, which
`cargo xtask published-rounds` writes from the vector fixtures (`--check` compares without
writing, as `scripts/check.sh` does); regenerate it whenever the vectors change. The terminal cell
widths of the line editor, `src/bin/mhfe/cell_widths.rs`, are written by
`python3 scripts/generate-cell-widths.py` from the same Unicode 18.0.0 database of `unicodedata2`
(`--check` compares without writing, as the Test vectors workflow does); regenerate it whenever the
Unicode version of the password rule changes.

Argon2 is the reference C implementation of its authors, vendored unchanged in
[`vendor/phc-winner-argon2`](vendor/phc-winner-argon2.md) and used by both the native tool and the
browser package. Version 0.3.0 was the last release to implement suite 2.

On x86-64 the Argon2 code is compiled twice: with SSE2, which every 64-bit x86 processor has, and
with SSSE3, which is 7 to 10% faster in the [measurements](docs/measurements/README.md). The program
checks the processor and runs the SSSE3 copy only where SSSE3 is present, so it also runs on older
AMD processors and on virtual machines that hide SSSE3. Both copies give byte for byte the same
results, and the tests run both.

The Rust source is licensed under MIT; see [`LICENSE`](LICENSE).

MHFE was written with extensive use of ChatGPT and Claude and went through numerous cross-checks and
audits, also made with these tools ([`docs/audits/`](docs/audits/README.md)).

## Questions

### Can MHFE find a missing word without the repair words?

Yes, within limits. Type `?` in place of the word in `mhfe decrypt`, `check`, `rekey` or `wallets`,
press Enter where MHFE asks for the repair words, and say what you know. MHFE then tries every word
the BIP39 checksum allows in that place, about 8 candidate containers for one missing word of 24 or
about 128 for one of 12, and compares each with what you know. A wallet is known by one of its
receiving or change addresses or by its master key fingerprint, typed in one field: eight hex digits
are taken as a fingerprint, anything else as an address, and MHFE then asks for its coin.

- **The container's own wallet** is the one its 24 words open when typed into a wallet as they are;
  MHFE shows its master key fingerprint under every container it makes. Each candidate is compared
  as it is, with no password and no recovery, on every core of the processor, which takes seconds
  for one missing word and up to a few minutes for two. For two missing words, MHFE looks for an
  address among the first 20 receiving and 20 change addresses of the first account, the usual gap
  of a wallet. It asks whether to go further, to 100, 500 or a number of your own, and
  `--scan-gap N` sets it.
- **Your wallet** is the wallet of the original seed phrase. MHFE recovers each candidate with your
  password and compares the result. Each candidate costs a full recovery, one to two minutes at the
  default settings, so one missing word takes about a quarter of an hour in a 24-word container
  (about 8 candidates) and two to four hours in a 12-word container of the same length (about 128).
- **The original seed phrase's passphrase** is all you type besides the password; you never type
  the phrase you are looking for. MHFE recovers each candidate and checks it by the original seed
  phrase itself: by its built-in check for a phrase of 12 to 21 words, and by the phrase +
  passphrase check for a 24-word phrase that `mhfe new` made with that check. A wrong candidate
  passes this 16-bit check about once in 65,536.
- **Nothing** is needed for an original seed phrase of 12 to 21 words: its built-in check tells the
  right candidate after each recovery. A 24-word original seed phrase without the phrase +
  passphrase check has no check at all, so nothing tells its candidates apart, and MHFE says so.

For a wallet, MHFE then asks whether a BIP39 passphrase is used with the container phrase or with
the original seed phrase, and asks for it only if you say yes, naming whose it is. For two missing
words, MHFE offers only the container's own wallet. For a container as long as its original seed
phrase, which has no check of its own, it offers the container's own wallet and, for one missing
word, also your wallet. After a refusal or a search that finds nothing, MHFE asks again what you
know; you type the container phrase only once.

Before a search that recovers candidates, MHFE says how long it takes, and it shows every word it
finds before it uses it. Without an address or the fingerprint of the container's own wallet, it
searches for one missing word only. Two missing words make about 16,000 candidates in a 24-word
container, which would take weeks to recover, and about 260,000 in a 12-word container of the same
length, which would take half a year to a year. That is the price of the protection itself: the
cost of a recovery that stops someone guessing your password stops a search through the words just
as much. MnemoCode, whose phrases are not encrypted, can try every candidate in a moment and so
finds two missing words with any fingerprint or address.

Repair words remain the way to rely on: a card of four words, kept apart from the container
phrase, restores up to four missing or unreadable words, or two wrong ones, at once and exactly,
without the password and without Argon2. Make them when you encrypt, or later with
`mhfe repair-words`; [`mhfe repair`](#mhfe-repair) says how they are used.
