# How MHFE works

MHFE protects a seed phrase while its backup is stored. It does not change the wallet's keys,
addresses or signature algorithms. A break in a coin's cryptography, including a future quantum
attack on its signatures, could put funds at risk regardless of how the seed phrase was stored.

For commands and backup steps, use the [README](../README.md#menu). The
[specification](https://github.com/hobby-eng/mhfe-spec) defines the exact bytes, proofs and
assumptions. MHFE remains experimental and has not been reviewed by independent cryptographers.

## The container

The default 24-word format encrypts a 256-bit block using your password. It runs twelve successive
steps, called Feistel rounds. Each step uses Argon2id, and its result is needed for the next step.
At the default settings, each Argon2id call uses 2 GiB of memory; one whole recovery takes roughly
one to two minutes on a current computer.

The encrypted 256 bits are written as 24 English BIP39 words. Those words also contain BIP39's 8-bit
checksum for copying errors. The container stores no password, salt field, format version, original
word count, PIM or memory level. Its word count identifies the format; keep the password and any
non-default settings separately. The same inputs always give the same container.

The same-length format encrypts only the random bits represented by the original words: 128 bits
for 12 words, up to 224 bits for 21 words. It has no extra space for the built-in recovery check.
For the cipher, those bits are split into equal halves of 64 to 112 bits. The value passed to
Argon2 as its salt is calculated from one half, so there are at most `2^64` to `2^112` different
salts for a round. The specification covers hidden wallets and decoys for this format, but does
not extend its attack-cost estimates for 24-word containers to it. See the
[format comparison](../README.md#24-words-or-the-same-length) before choosing it.

The specification names the 24-word format **suite 3**, and the same-length format **suite 4**.
These are protocol identifiers, not settings you need to supply during recovery.

## What the checks establish

| Check                      | What it can tell                                                                                    |
| -------------------------- | --------------------------------------------------------------------------------------------------- |
| Container's BIP39 checksum | Most copying errors; it does not test the password                                                  |
| Built-in check             | A likely correct password, settings and original length for a shorter phrase in a 24-word container |
| Creation check             | The newly produced container recovers to the phrase supplied for this operation                     |
| Phrase + passphrase check  | Statistical evidence for a pair used with that optional profile                                     |
| Known wallet address       | The recovery derives that address within the searched paths                                         |
| Master key fingerprint     | The recovery matches a 32-bit wallet identifier                                                     |

Before making a 24-word container, MHFE has 256 bits available for the original phrase and its
built-in check. A shorter phrase needs fewer bits for its random data, leaving room for the check:

| Original seed phrase | Random data from the phrase | Bits left for the built-in check |
| -------------------- | --------------------------- | -------------------------------- |
| 12 words             | 128 bits                    | 128 bits                         |
| 15 words             | 160 bits                    | 96 bits                          |
| 18 words             | 192 bits                    | 64 bits                          |
| 21 words             | 224 bits                    | 32 bits                          |
| 24 words             | 256 bits                    | None                             |

MHFE fills the remaining bits with a hash of the phrase's data bytes, then encrypts the entire
256-bit block. After decryption, it recalculates the hash for each possible shorter word count and
compares it with those saved check bits. A match selects that word count. Several counts can match
by rare chance. A 24-word original fills all 256 bits with its random data, so there is no room for
this built-in check. The finished container has no empty bits; the extra check information is
encrypted along with the phrase.

A wrong password applied to a 24-word original seed phrase or a same-length container gives another
valid phrase. Its BIP39 checksum cannot distinguish it from the intended one. An address or
fingerprint of the intended wallet supplies an independent comparison. An address searched over a
limited range can fail to match because the correct path lies outside that range.

The creation check covers the words the program produced, not the copy you wrote down. It detects
a difference during that check; passing does not rule out all hardware faults. Rehearse from your
finished backup with [`mhfe check`](../README.md#mhfe-check).

## The optional wallet check

A new 24-word phrase can be drawn so that it passes **MHFE-WALLET-CHECK-SEED-1** with a nonempty
BIP39 passphrase; MHFE does not draw phrases, but checks such a phrase when it recovers it. The
Deriver of the [multi-chain wallet tools](https://github.com/hobby-eng/multi-chain-wallet-tools)
draws one. The BIP39 seed is the 64 bytes a wallet derives from the phrase and passphrase before
making its keys. This check hashes that seed and requires the first 16 bits of the hash to be zero.
Finding a phrase that passes takes about 65,536 sequential trials on average, leaving about 240 bits
of randomness from the original 256. The [API reference](API.md#wallet-check) gives the digest and
published examples; the specification defines the [draft
profile](https://github.com/hobby-eng/mhfe-spec#optional-source-profile-a-recovery-check-for-new-24-word-phrases).

A wrong password or passphrase passes about once in 65,536. A pass does not identify a wallet and
cannot confirm a rekey. A phrase made without this profile almost always fails it, so a failure
matters only when the phrase was deliberately drawn to pass.

Keep funds only in the wallet with the passphrase, leaving the wallet without one unused. Otherwise
its blockchain history can confirm the MHFE password on its own, allowing the password and
passphrase to be searched separately. The check is only as strong as the passphrase.

The passphrase is fixed for this check when the phrase is drawn. A different one passes only by
chance or after a search, about 65,536 trials on average. Finding a decoy MHFE password whose
recovered phrase passes takes about 65,536 full recoveries instead. A passing phrase is itself
statistical evidence that the profile may have been used. The specification's deniability results
for a uniformly random original seed phrase do not by themselves cover phrases selected to pass this
check.

A program that draws such a phrase should keep neither the count of its trials nor their duration:
the proof assumes a draw that reveals neither. This profile applies to new wallets only; keep a
compatible program with the backup.

## Hidden wallets and decoys

A **hidden wallet** is derived from a genuine wallet's container using another MHFE password. You
can disclose the genuine wallet while keeping that extra wallet unmentioned. A **decoy wallet**
serves as the wallet you disclose. Which password can credibly stand in for the genuine one depends
on the original phrase and its checks.

The container can also be used directly as a BIP39 phrase. These arrangements are optional and use
independent passwords and passphrases:

```text
Container phrase
│
├── entered directly into a wallet
│   ├── without a BIP39 passphrase ...... empty wallet or small decoy
│   └── with its own BIP39 passphrase ... prepared decoy wallet
│
├── recovered by MHFE with another password
│   └── another valid phrase
│       ├── without a BIP39 passphrase .. hidden wallet or decoy
│       └── with its own BIP39 passphrase additional wallet
│
└── recovered with your MHFE password
    └── your original seed phrase
        ├── without a BIP39 passphrase .. your wallet
        └── with its BIP39 passphrase ... your wallet under that passphrase
```

Anyone who can read the container can spend funds in its wallet without a BIP39 passphrase. A decoy
wallet opened directly from the container can conceal the encrypted wallet only from an adversary
who does not know that MHFE was used. Enter it only into a wallet you trust: a stored copy also lets
its holder try MHFE passwords offline. If you prepare a decoy passphrase for that wallet, whoever
receives both can spend its funds; keep that amount within what you can afford to lose.

For a 12- to 21-word original seed phrase in a 24-word container, the built-in check recognises the
genuine password. An optional wallet check can likewise distinguish a checked phrase when its
passphrase is known. Extra wallets can still remain hidden, but an arbitrary password cannot
credibly replace the recognised genuine one.

For a 24-word original seed phrase without the optional wallet check, or a same-length container,
every password gives an unverified phrase. Another password, chosen as randomly as the real one,
can then serve as a decoy if its wallet has a believable balance and history. The specification's
analysis has limits: all copies must hold the same container; knowledge of a shorter original
length can distinguish a decoy 24-word reading; and another record, such as a hardware wallet or
paper backup, must not contradict the disclosure.

A blockchain history can supply a password check even when the container has none. Funds under an
independent BIP39 passphrase, with the wallet without it left unused, avoid that particular check:
the MHFE password and passphrase must then be guessed together. This claim depends on the
specification's model and the wallet data available to the adversary.

The [README's recovery section](../README.md#several-passwords-and-hidden-wallets) explains how to
open several readings and the records or transfers that can expose hidden wallets. Rekeying moves
only the confirmed original seed phrase. Other wallets remain tied to the old container and
settings.

## Repair-card limits

The optional [MHFE-REPAIR-1
profile](https://github.com/hobby-eng/mhfe-spec#optional-repair-words-mhfe-repair-1) computes extra
check information from the numbers of the container's words in the BIP39 list. The error-correcting
code used for this is Reed–Solomon. With `k` repair words it can repair `s` unreadable words and `e`
wrong words when `2e + s <= k`. It needs no password or Argon2 computation.

Beyond that bound, or with a card from another container, repair can fail or produce a different
checksum-valid container. A successful decode therefore does not confirm the backup or wallet.

The card alone also narrows the possible containers. In the idealized checksum model, eight repair
words leave roughly `2^168` checksum-valid candidates for a 24-word container, but roughly `2^40`
for a 12-word one. These counts do not identify the intended container or bypass its MHFE password.
They do make the card a partial copy of the container; give it the same protection and keep it
apart from the backup.
