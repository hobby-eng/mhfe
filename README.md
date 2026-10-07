# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics

[![CI](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml)
[![Release](https://github.com/hobby-eng/mhfe/actions/workflows/release.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/release.yml)
[![Test vectors](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml)
[![RustSec audit](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Build provenance: GitHub attestations](https://img.shields.io/badge/build%20provenance-GitHub%20attestations-2ea44f)](https://github.com/hobby-eng/mhfe/attestations)

<p align="center">
  <img src="assets/mhfe-mascot.png" alt="MHFE penguin mascot carrying a cold-storage plate" width="240">
</p>

<p align="center"><sub>The penguin lives in the cold, like the backups MHFE is made for. It holds a
steel plate with 24 words and waddles from side to side, much as a Feistel network swaps its two
halves in every round.</sub></p>

MHFE turns the seed phrase of a Bitcoin or other BIP39 wallet (12, 15, 18, 21 or 24 English
words) into a password-protected **container of 24 words**, or, if you choose so for a phrase of 12
to 21 words, a container **of the same length** as your phrase. The container is itself an
ordinary, valid seed phrase, so it fits the same metal plate or capsule. With the password it turns back
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

MHFE is made for **cold storage**: a backup of a seed phrase that is written once on paper or a
metal plate, put away, and read again perhaps years later on an offline computer. It is not meant
for a wallet in daily use.

**Any phrase becomes 24 words.** MHFE accepts a phrase of 12, 15, 18, 21 or 24 words and always
gives a container of 24 words. Inside, the original becomes a 256-bit number that twelve rounds of a
Feistel cipher scramble. Each round takes its key from the password through Argon2id, with 2 GiB of
memory, and needs the result of the round before, so every guess of the password costs the full
work. The result is written out as 24 words with an ordinary BIP39 checksum: the container is itself
a valid seed phrase, fits the same plates, and nothing in it shows that MHFE made it. No salt,
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

### 24 words or the same length

For a phrase of 12, 15, 18 or 21 words, MHFE can instead give a container with as many words as the
phrase, if you choose it; 24 words stays the default. The backup then keeps its length and looks
like any other phrase of that length. The price is real, so MHFE asks first; the question links
here, and `?` at it compares both:

| Container             | A wrong password                             | Shows the length of your phrase | A miscopied word slips through                | Tells a guesser the right password       |
| --------------------- | -------------------------------------------- | ------------------------------- | --------------------------------------------- | ---------------------------------------- |
| 24 words (default)    | is detected: MHFE tells you (12 to 21 words) | no, every container has 24      | about once in 256                             | yes, through the built-in check          |
| Same length as phrase | gives another valid phrase, with no error    | yes                             | about once in 16 (12 words) to 128 (21 words) | no, only a wallet's history on the chain |

The same-length container has no room for a built-in check, so only a comparison with your wallet,
with `mhfe check`, confirms a recovery. Like a 24-word original, it turns into a valid phrase with
any password. The [specification](https://github.com/hobby-eng/mhfe-spec) defines this format as
suite 4; its analysis of plausible deniability covers this format too, while its estimates of what
an attack costs are stated for the 24-word format only.

**Convenience or secrecy.** The choice is between a recovery that checks itself and a container
that gives nothing away. The built-in check tells you at once that a password is wrong, but it
tells someone who has the container the same: a guesser recognises the right password when it
comes, although each guess still costs a full recovery. A same-length container, like a 24-word
original, gives a valid phrase for every password, so the container alone cannot tell a right
password from a wrong one; this is what makes plausible deniability (below) possible. A guesser can
then recognise the right one only through a wallet with a public history: if the wallet of the
phrase itself, used without a BIP39 passphrase, has ever received funds, the blockchain shows it,
and that confirms a right password just as the built-in check would. Only funds kept under a BIP39
passphrase, with the wallet without it never used, leave no such trace; the password and the
passphrase then have to be guessed together.

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
> word, belongs to the wallet: a wallet asks for it together with the seed phrase, and it stays
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
    └── your original seed phrase
        ├── without a BIP39 passphrase ....... your wallet
        └── with its own BIP39 passphrase .... your wallet: the strongest arrangement
```

**The container as a wallet.** Every wallet accepts the 24 words as an ordinary seed phrase.
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
in the archive, it shows a menu of the same commands. Its questions
offer their answers as a list: choose with the arrow keys and Enter, or press an answer's number;
Escape cancels.

Every command that handles a secret first tests every part of the program on this computer, in a
fraction of a second, and stops before its first question if one gives a wrong answer;
[`mhfe self-test`](#mhfe-self-test) says what it tests.

Use it on a trusted computer that stays offline while the phrase and the password are on it, best a
Linux system started from a USB stick with the network off. On Linux MHFE also applies kernel
restrictions against creating sockets and opening files for writing; the command's summary shows
which restrictions took effect, as MHFE confirms by trying what each one forbids, and warns when one
the kernel reported does not hold. A command started directly, not from the start menu, also runs in
its own network namespace where the system allows it, with only inactive loopback and no external
routes. Descriptors already open remain usable, including sockets and redirected output, so these
restrictions do not replace a trusted offline environment. On Windows, Windows PE from a USB stick
is better than your everyday system; `mhfe.exe` needs nothing beyond Windows itself, though it has
not been tested in Windows PE yet.

Swap matters too. The system may write memory to a swap area on a disk, Argon2's work area
included, from which a password guess can be tested cheaply, and it can stay there for years. On
Linux MHFE therefore warns when a swap area is not encrypted. Use a computer with encrypted swap or
none: a live system started from a USB stick usually has none, macOS encrypts its swap, and on
Windows use BitLocker or no page file. The summary of a command also says whether the secrets you
type are kept in locked memory, out of swap, or warns when the system refused to lock it.

## Commands

`mhfe <command> --help` explains every option. Keep a copy of this program offline as well, so that
a compatible version is at hand years from now. While a command runs, its screens keep to short
lines; a grey "More:" line links to the section here that explains them. At a terminal, each step
of a command has a clean screen of its own, and when the command ends the main screen keeps only a
short summary of the answers and results.

The line under every seed phrase or container that mhfe shows gives its master key fingerprint:
eight hexadecimal digits that wallet apps show to tell wallets apart (Sparrow calls it "Master
fingerprint"). A BIP39 passphrase changes it, so the line says which wallet it is for: with your
passphrase in `mhfe new`, and otherwise the wallet without one, since `mhfe decrypt`, `rekey` and
`wallets` do not know the passphrase it is used with; for a wallet with one, `mhfe check
--fingerprint` compares the fingerprint your wallet app shows. Under a container, it is the
fingerprint of the container's own words, not of your wallet: do not note it as your wallet's. The
line appears where the words appear, never in the summary or in the output for scripts.

### `mhfe password`

`mhfe password` makes a password of random words from the
[EFF dice list](https://www.eff.org/dice) of 7,776 words: use four, better five. `--dice` uses real
dice, `--words N` sets the count. `--chars N` makes N random characters instead (16 by default,
about 93.3 bits) from 57 letters and digits without look-alikes such as 0 and O; words are easier
to type correctly years later. Any text on one line can be a password, but control characters
such as a tab are refused, and letter case and spaces count: lowercase words with single spaces
are the easiest to type again years later. The password is not your wallet's BIP39 passphrase.

The password is shown only once and is not stored: write it down and keep it apart from the
container. Random words or characters are both drawn from the system's cryptographic random
generator, every one equally likely.

`mhfe encrypt` estimates the strength of the password you type and warns below about 50 bits,
a little under four dice words. The estimate is rough and uses nothing from outside the program: it
knows the words of the EFF and BIP39 lists, common passwords, years, repeats, runs such as `1234`
and keyboard rows such as `qwerty`, also with substitutions such as `0` for `o`. It can overrate a
password made of words it does not know, such as names or words of other languages. A password
from `mhfe password` has a known strength.

From the start menu, the entry first asks for five dice words, five words and a check word, or
sixteen random characters; Enter then makes another password of the same kind and Escape returns to
the menu. Each password replaces the previous one on the private screen; leaving it clears the
screen.

#### A check word

`mhfe password --check-word` makes five words and a sixth computed from them, the check word, as the
optional profile
[MHFE-PASSWORD-CHECK-1](https://github.com/hobby-eng/mhfe-spec#optional-password-check-word-mhfe-password-check-1)
of the specification defines it. When you type such a password, mhfe compares its words with the
list before the long wait:

- the words fit their check word: the summary says so;
- one word is forgotten and typed as `?` in its place, as the password screen says, or misspelt:
  the check word restores it, and mhfe shows the word and asks before using it. A word simply left
  out does not work, since five words are an ordinary password;
- every word is in the list but they do not fit: one is wrong, and which one cannot be told. mhfe
  shows the six possible repairs, one for each place, to compare with what you wrote down.

Spaces and capitals count in such a password as in any other. When its words fit their check word
only once they are written in small letters with single spaces, mhfe offers that corrected
password as well, also together with a repair.

mhfe never repairs anything without asking and never refuses a password: the container does not
record whether its password has a check word, so the password as typed is always one of the answers.
A check word that fits shows only that the six words belong together, not that the password opens
this container. Type the words in lower case with single spaces, as shown.

The check word adds no strength: the password keeps the 64.6 bits of its five random words, and the
check word must stay as secret as the rest, since anyone who learns it alone has about 51.7 bits
left to guess. If you may give away another password of the same container, such as the one of the
main wallet in front of hidden ones, make both with `--check-word`, so that they look alike.

### `mhfe encrypt`

`mhfe encrypt` asks for the phrase and twice for the password, as a mistyped password would lock the
phrase away for good. Both are typed on a private screen that shows what you type and is cleared as
soon as you are done; a mistyped word is refused by the word list or the checksum. For a phrase of
12 to 21 words it next asks how long the container should be: 24 words, the recommended default, or
the same length as your phrase; `?` explains both, and `--same-length` chooses the same length
without asking. At a terminal it then asks, for every phrase, whether its wallet has a BIP39
passphrase. MHFE encrypts the phrase, not the passphrase, so a wallet with one still needs it; the
answer only decides whether the list of what to keep names it, and the passphrase itself is not
asked for. Neither answer is marked at first, so that a hurried Enter cannot leave the passphrase
off that list: the hint below the list says "Enter selects once one is marked", and Enter does
nothing until an arrow key has marked an answer, while 1 or 2 chooses at once. Where the answers
come as a numbered list instead, the prompt `Choice:` has no default: type the number, as an empty
line is refused. After the encryption it shows the format of the container, the suite identifier.
The words of the seed phrase may be typed in any case or as their first four letters; the password,
by contrast, must be typed exactly, letter case and spaces included. The container appears after one
to two minutes, on a private screen like the phrase: write it down while MHFE checks it by
recovering your phrase from it, and rely on it only once it says "Verified". Enter or Escape then
clears that screen, so that the container leaves no copy in the terminal's history; press it only
once you have written the words down and checked them. With the default settings the container's
words and the password are all MHFE needs; in the rare case that MHFE asks you to note the word
count, do so. The same phrase, password and settings always give the same container, so a lost plate
can be made again, and two identical containers reveal the same phrase: use a different password for
each phrase.

After the encryption MHFE lists what to keep: the container's words and the password, the wallet's
BIP39 passphrase if it has one, and, only where needed, the repair words, changed settings or the
word count. With `--stdin` nothing asks about a passphrase, so the list ends "also the wallet's
BIP39 passphrase, if it has one". Use the password for this phrase and nowhere
else, and make another copy of the container only by copying its words exactly. Before you rely on
the container, rehearse the recovery with `mhfe check`, typing the words from the plate or paper
you wrote, not from the screen, and keep the original backup until it matches. This matters most
for a container of the same length: its shorter checksum lets a miscopied word through more often,
and the container then opens another wallet without any error.

### `mhfe check`

`mhfe check` rehearses a recovery before you rely on a container and shows only "matches" or
"does not match", never the phrase; for a matched address it also shows where it was found, such as
`m/84'/0'/0'/0/5`. Type the container from the plate, not from the screen: one
miscopied word passes the BIP39 checksum in one case in 256, or as often as one in 16 for a
12-word container of the same length, and for a 24-word original or a same-length container
silently gives another wallet. A same-length container has no built-in check, so compare it with
your wallet. Compare with a receiving address of the wallet, the strong check that also
covers a BIP39 passphrase, or with the master key fingerprint, quick but only 32 bits. The address
may be one of twelve coins: Bitcoin, Ethereum and every EVM network (BNB Smart Chain, Polygon,
Avalanche C-Chain, Arbitrum, Optimism, Base and others), XRP, Tron, Zcash (transparent addresses),
Dogecoin, Bitcoin Cash, Litecoin, Ethereum Classic, Cosmos, Injective and Dash, both Dash Core
`X…` and Dash Platform payment `dash1k…` addresses (DIP17, on `m/9'/5'/17'/account'/0'-1'/index`).
Shielded addresses of Zcash (`zs1…`, `u1…`) and Dash (Orchard, `dash1z…`) are refused with that
reason: their keys need their own cryptography, so use the same wallet's transparent `t1…` or Dash
`X…` or `dash1k…` address. MHFE asks for the
coin, or takes it from `--coin`; a script without `--coin` compares with a Bitcoin address and says
so ([For scripts](#for-scripts)). Before the check it shows what it searches: the first 100
receiving and change addresses of accounts 0 to 9 on the standard paths of that address, or one
path with `--path`. Do not keep the address or fingerprint next to the container.

For a phrase drawn so that its BIP39 seed passes a check, as `mhfe new` does on request and other
programs following the specification can, the list also offers "The phrase + passphrase check" for
a 24-word container: a 16-bit hash of the seed, which BIP39 derives from the phrase and the
passphrase together. It asks for the BIP39 passphrase, which may not be empty, compares the
container's 24-word reading only, and confirms the password and passphrase, not the wallet. "The
container's built-in check" is the one of a 12- to 21-word original in a 24-word container.

When it does not match, the check cannot tell what is wrong: the password, a setting, the
container, the BIP39 passphrase or the reference. Without an address or fingerprint, for a 12- to
21-word original in a 24-word container, it uses the container's built-in check, which proves the
password and settings but not the wallet or its passphrase.

### `mhfe decrypt`

`mhfe decrypt` gives back the original phrase. The container is typed on a private screen,
which shows it as you type it; the phrase then appears on a
private screen as well, which Enter or Escape clears once you have written it down. Neither stays
in the terminal's history; the summary shows the container's format. The number of words tells it the format: 24 words is the default format, 12 to 21 words a
container of the same length. For a 12- to 21-word original in a 24-word container it confirms the
password and finds the length itself; a wrong password then shows as "Not verified". A 24-word
original and a same-length container have no such check: a wrong password gives another valid
phrase, so compare the result with your wallet. A new 24-word phrase can be made with a check of
its own, as the specification allows. For a phrase made with it and without a BIP39 passphrase,
MHFE says in one line when the recovered phrase passes that 16-bit check, and nothing when it does
not: a phrase made without the check fails it, so a failure tells nothing. A pass makes a right
password very likely but does not show which wallet it is; with a passphrase, `mhfe check` tests
it. `--words N` sets the length of the original
yourself; it then accepts only a 24-word container or a same-length container of exactly N words.
For about one container in four billion, several lengths pass their check by accident; MHFE then
shows each reading, and you compare them with your wallet or choose the length with `--words N`.

### `mhfe rekey`

`mhfe rekey` puts the same seed phrase into a new container, under a new password, new settings or
both. It asks for the old container, its password and settings, and, for a 24-word container, the
length of your phrase. Before it encrypts anything again, it confirms the recovery. A 12- to
21-word phrase in a 24-word container passes its built-in check at that length, with nothing to
choose. A 24-word phrase or a container of the same length has no such check, so a list asks how to
confirm it: by a receiving address or the master key fingerprint of your wallet, as `mhfe check`
compares them, or by "Show me the phrase", which shows it to you on a private screen to compare
word for word with an independent written record of it, such as the original backup. From memory
such a comparison confirms little; without a record, use an address or the fingerprint. Encrypting
under the old password and comparing would prove nothing, so it does not offer that.

Whatever confirms the recovery, it then asks once whether the wallet has a BIP39 passphrase, as
`mhfe encrypt` does and with neither answer marked at first, so that the list of what to keep names
it. The question comes before any address or fingerprint is typed: one compared without a
passphrase matches only the wallet of the phrase alone, which says nothing about funds kept under a
passphrase. After an address or the fingerprint, MHFE asks for the passphrase only if the wallet
has one, and refuses an empty one, since you said there is one; a wallet without one is not asked
for it at all. All of this comes before the long work starts. Then it asks for the new settings and
password and makes the new container as `mhfe encrypt` does, in the same format as the old one.

The old container is not revoked: with the old password it still opens your wallet. Rehearse the
new plate with `mhfe check`, best on another day, and only then destroy every copy of the old one.
Until then two containers of the same phrase exist, which plausible deniability does not cover.

Every wallet that another password opens on the old container, such as a decoy, is a different one
on the new container: move its funds first. MHFE says so every time and asks every user to confirm
that the funds of any such wallet are moved or backed up another way, without asking whether such
a wallet exists, as an answer would be a record of it; "No" stops before anything is typed. The
result says once more that the old plate still opens the wallet with the old password.

The phrase is shown for the comparison only on a private screen. Where none can be opened, such as
when the output goes to a file, that choice is not offered.

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
- **A phrase + passphrase check**, for funds kept under it. The phrase is drawn so that a
  tagged SHA-256 of its BIP39 seed, made with the passphrase, starts with 16 zero bits; the exact
  bytes are in [docs/API.md](docs/API.md). `mhfe check` with the passphrase then says whether a
  recovery passes. A wrong password or passphrase still slips through once in about 65,536, so a
  pass is strong evidence, not proof, and only an address or the fingerprint shows which wallet it
  is. A guess of the password can be tested only together with a guess of the passphrase. Drawing
  the phrase this way leaves about 240 of its 256 bits, still far beyond any search.

The check has costs:

- Keep all funds in the wallet the passphrase opens. The wallet of the phrase alone stays empty and
  is never used: its public history would let an attacker confirm the MHFE password on its own, and
  the searches would add instead of multiplying. The check is only as strong as the passphrase, and
  MHFE warns about a weak one.
- The passphrase is fixed when the wallet is made. Another one fails the check, except by chance
  or when someone searches for one that passes, which takes about 65,536 tries; a decoy MHFE
  password passes only after about 65,536 recoveries.
- A phrase that passes is statistical evidence that it was made this way, since a random one
  passes once in about 65,536.
- The specification's deniability results assume a uniformly random phrase and do not by
  themselves cover a phrase drawn to pass the check.
- It is for new wallets only: the draft profile MHFE-WALLET-CHECK-SEED-1, which the
  specification defines as an
  [optional source profile](https://github.com/hobby-eng/mhfe-spec#optional-source-profile-a-recovery-check-for-new-24-word-phrases).
  It is still experimental. Keep a copy of this program with the container.

### `mhfe wallets`

Every password other than the container's own opens another valid 24-word wallet on a 24-word
container. `mhfe wallets` shows the wallet each password you type opens, so that one container can
carry hidden wallets behind the one you could disclose: under pressure you give the container's own
password, and the wallet it opens, with its genuine history, is all anyone sees. The specification
describes this as a hidden wallet behind an honest disclosure.

Nothing is created or stored: the container and a password give the same wallet every time. A hidden
wallet exists only as the output of the program, and any correct program must find it again later,
so run `mhfe self-test --vectors` once on the computer before you fund one. All wallets appear on
one private screen, together with their passwords, which is cleared at the end, so the main screen
shows neither the wallets nor how many you opened; without a private screen the command refuses to
start. A wallet need not be written down, as the container and its password give it again, and
nothing records which passwords you used or how many. A password whose wallet passes the built-in
check of a shorter phrase, as the container's own password of a 12- to 21-word phrase does, is
refused, so that recovery never calls a hidden wallet verified. So is one whose wallet passes the
check of a new phrase, with the main wallet's passphrase or without one.

To keep a hidden wallet hidden:

- Fund it only from sources linked neither to you nor to the main wallet. Moving money from the
  main wallet to it links the two.
- It depends on the exact container and settings. `mhfe rekey`, another suite, a forgotten password
  or the loss of every copy of the container loses it, unless its funds were moved first.
- Give each a strong password of its own, different from the container's own and from the others.
- A watch-only copy of it on an everyday device is evidence of it.

Hidden wallets have 24 words for now.

### `mhfe repair`

A plate can rust, be scratched or be copied with a wrong word. Repair words are a few extra words,
kept on a card apart from the plate, with which MHFE repairs the plate without the password: each
repair word repairs one word that cannot be read, and two repair one word that is wrong. When you
make a container with `mhfe encrypt`, `mhfe new` or `mhfe rekey`, MHFE asks whether you want them,
four recommended:

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

`mhfe repair` repairs a plate: type its words with `?` for each word you cannot read, then the
repair words, with `?` where needed too; the card can be typed as written, with its name and
numbers. A word that is not in the BIP39 list counts as unreadable, and four letters of a word are
enough. It shows the repaired container and every word it repaired with what was read there,
never repairing silently; write them on the plate and rehearse with `mhfe check`. A detected
decoding failure or invalid BIP39 checksum is rejected. Damage beyond the code's bound, or a card
from another plate, can instead produce a wrong result that passes the checksum; the program cannot
always recognise this. Successful decoding is therefore not confirmation of the intended wallet.

Keep the card apart from the plate, so that one accident or one thief does not take both, and guard
it like the plate: a container is what someone needs to try passwords, and whoever finds the card
together with a damaged or partial copy of the plate can repair that copy as you can. The card
alone also reduces the number of possible containers: eight repair words leave roughly `2^168`
checksum-valid candidates for a 24-word container, but roughly `2^40` for a 12-word container in
the idealized checksum model. These counts do not identify the true container or bypass its MHFE
password, but the card is a partial copy and must be protected accordingly. The repair words use
the optional Reed–Solomon profile
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
formats and the length detection, the password rules, the word list, repair words, the check word,
the password generator and the test that refuses a broken random generator, wallet keys and
addresses, the paths an address check says it will search, the wallet check, hidden wallets, rekey
and the rehearsal check. The rounds are replayed with the keys that the published MHFE vectors
record, so this needs no 2 GiB of memory. The command also reads back that core dumps are off, which
of the kernel's restrictions hold and whether memory can be locked. All of this takes a few
hundredths of a second, uses public test data only and shows nothing when every part passes.

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
ones. Only this shows a fault that appears only at Argon2's full size, which an encryption would
not notice either, since it would encrypt and check in the same wrong way. When a result is not as
published, it says where the work first left the published path. In the first round that went
wrong, Argon2id was either given an input, password or salt, that the published vector does not
have, so the fault lies before Argon2id, in that round's password or salt or in what the round
started from; or it was given the published input and returned another key, so the fault lies in
Argon2id. When every Argon2id input and key is as published, the fault lies after the last Argon2id
call of the encryption or the recovery. Run it once before you trust a computer with a real phrase,
and before you fund a hidden wallet. The start menu's entry asks which of the two tests to run.

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
same code in a web page, for example in the offline wallet tools, and offers everything the
command-line tool does except what only an operating system or a terminal can give, such as memory
levels above 0. It is a set of independent module classes, each usable alone, over one shared
WebAssembly: the encryption core, repair words, the password tools and the wallet tools. Encryption
and recovery have two modes:

- **Standard mode** works everywhere, also in a page opened as a file. Argon2 runs on one thread, so
  a recovery takes about four to seven minutes, and an encryption about twice that.
- **Fast mode** runs the four Argon2 lanes in parallel, about a quarter slower than the command-line
  tool. A browser allows this only on a specially served page. `mhfe serve tool.html` serves one
  HTML file from this computer (127.0.0.1) with the headers that enable it and opens it in the
  browser. It sees none of your secrets: all the work happens in the page. When a tool and its
  checksum file lie next to the program, the first entry of its menu serves that tool, so a
  double-click is enough. On a computer with Python 3.8 or later but without the mhfe program,
  `python3 mhfe-fast-mode.py tool.html` from the browser package's core does the same. Both serve a
  page only when its checksum file `mhfe-fast-mode.sha256` lies next to it and matches.

A browser supports memory level 0 only. It never connects to anything either: the package loads no
remote resources.

Each module of the package tests its parts in the same way before its first use and refuses to work
if one fails; a page can also run the longer test and, on request, the published vectors. The longer
test names what a browser cannot test, such as core dumps or locked memory, with the reason. Files
of different builds of the package are refused before they work together, even when only one script
differs. An Argon2 build that the browser does not start gave no wrong answer, so it is no failure:
the test says why Argon2 is not available, or, when only the fast mode's build does not start, that
it tested the standard mode's build instead.

Both kinds of container work there too: a page asks for the same length with `sameLength: true`
in its `encrypt` call, and recovery takes either kind.

## For scripts

`--stdin` reads the answers from standard input, one per line, instead of asking:

- `encrypt`: the phrase, the password, and the password again; the container has 24 words unless
  `--same-length` is given. Nothing asks whether the wallet has a BIP39 passphrase, so the list of
  what to keep ends "also the wallet's BIP39 passphrase, if it has one";
- `decrypt`: the container and the password;
- `check`: the container and the password, then with `--address` or `--fingerprint` the reference
  and the BIP39 passphrase (an empty line if the wallet has none); with `--words N` nothing more.
  `check --stdin` needs one of these three options, because it cannot ask which reference to use.
  Nor can it ask for the coin: `--address` without `--coin` means a Bitcoin address, as in earlier
  versions. The summary then says "Bitcoin, as no --coin was given", and an address that is not
  Bitcoin's is refused with a message that names Bitcoin and `--coin`; give `--coin`, such as
  `--coin ethereum`, for an address of another coin.

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

| Code | Meaning                                                                                      |
| ---- | -------------------------------------------------------------------------------------------- |
| 0    | Done; for `check`, the recovery matches                                                      |
| 1    | Internal error, a failed self-test, or a failed check of a new container, which is not shown |
| 2    | Invalid input: phrase, container, password, setting, address or option                       |
| 3    | Does not match: wrong password, PIM, memory level, container or selected length              |
| 4    | Not enough memory for the memory level                                                       |
| 130  | Cancelled: Ctrl+C, Escape or q at a list, Ctrl+D at a secret's prompt, or No in `rekey`      |

A command is cancelled with Ctrl+C at any moment, with Escape, or q, at a list of answers, with
Ctrl+D on the empty prompt of a secret, and in `mhfe rekey` with "No, stop" when it asks whether
the funds of other wallets on the container are moved or backed up. Ctrl+C stops the tool at once,
also in the middle of a round; the operating system then discards its memory.

## Release files

A release has archives for Linux (x86-64 and ARM64), macOS (Intel and Apple silicon) and Windows
(x86-64), each with the `mhfe` program, its launcher and the licences, and the browser package. One
x86-64 program fits every 64-bit x86 processor: it uses SSSE3 where the processor has it, 7 to 10%
faster ([measured](docs/measurements/README.md)), and SSE2 otherwise.

Check a download against the release's `SHA256SUMS` before you use it, and from v0.5.0 check the
OpenPGP signature of that file too: import `RELEASE-SIGNING-KEY.asc` from the release, compare its
fingerprint with `28FC51B1DB80DF2101128CB30EDD4814591DD095`, as given in
[docs/RELEASING.md](docs/RELEASING.md) and at `https://github.com/hobby-eng.gpg`, then run:

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

Every release file also has a signed build provenance: GitHub records which run of the release
workflow built it, from which commit. Check it on the computer you downloaded the file with, since
the check needs the network, and only then carry the file to the offline computer:

```bash
gh attestation verify mhfe-v0.5.1-linux-x86_64.tar.gz --repo hobby-eng/mhfe
```

## For developers

To build from source, install Rust and run `cargo build --release --locked`; the program is then
`target/release/mhfe`. Release builds and the scripts below replace the builder's own paths in the
program and the WebAssembly (`packaging/remap-builder-paths.sh`), so they refuse `RUSTFLAGS` and
`CARGO_ENCODED_RUSTFLAGS`; give extra flags per target, such as
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS`.

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
password rule on every case of the specification. The tests at start replay the published vectors
from `src/mhfe/published_rounds.rs`, which `scripts/generate-published-rounds.py` writes from
those fixtures (`--check` compares without writing, as `scripts/check.sh` does); regenerate it
whenever the vectors change.

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
