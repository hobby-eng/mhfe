# How MHFE works

MHFE protects a seed phrase while its backup is stored. It does not change the wallet's keys,
addresses or signature algorithms. A break in a coin's cryptography, including a future quantum
attack on its signatures, could put funds at risk regardless of how the seed phrase was stored.

For commands and backup steps, use the [README](../README.md#menu). The
[specification](https://github.com/hobby-eng/mhfe-spec) defines the exact bytes, proofs and
assumptions. MHFE remains experimental and has not been reviewed by independent cryptographers.

## The container

The default format, suite 3, maps an English BIP39 phrase to a 256-bit state. Twelve Feistel rounds
transform it using the password. Each round calls Argon2id and depends on the preceding state. At
the default settings, each call uses 2 GiB of memory; one whole recovery takes roughly one to two
minutes on a current computer.

The result is written as 24 English BIP39 words with a normal checksum. It stores no salt, suite
version, original length, PIM or memory level. The suite is inferred from the container's word
count; the password and any non-default settings must be kept separately. The same inputs always
give the same container.

Suite 4 works directly on a shorter phrase's entropy, so the container has the same 12, 15, 18 or
21 words as the original seed phrase. It has no space for a built-in recovery check. Its state has
128 to 224 bits, split into halves of 64 to 112 bits; a round's salt therefore comes from at most
`2^64` to `2^112` values. The specification extends its deniability analysis to this format, but
its suite 3 attack-cost estimates do not cover it. See the
[format comparison](../README.md#24-words-or-the-same-length) before choosing it.

## What the checks establish

| Check                      | What it can tell                                                                       |
| -------------------------- | -------------------------------------------------------------------------------------- |
| Container's BIP39 checksum | Most copying errors; it does not test the password                                     |
| Built-in check             | A likely correct password, settings and shorter original length in a suite 3 container |
| Creation check             | The newly produced container recovers to the phrase supplied for this operation        |
| Phrase + passphrase check  | Statistical evidence for a pair used with that optional profile                        |
| Known wallet address       | The recovery derives that address within the searched paths                            |
| Master key fingerprint     | The recovery matches a 32-bit wallet identifier                                        |

A 12- to 21-word original seed phrase leaves unused bits in suite 3's state. MHFE fills them with a
hash of the phrase, called the verifier. Recovery compares each shorter reading with its verifier;
a passing built-in check selects that length. Several lengths can match by rare chance. A 24-word
original seed phrase fills the whole state and has no verifier.

A wrong password applied to a 24-word original seed phrase or a same-length container gives another
valid phrase. Its BIP39 checksum cannot distinguish it from the intended one. An address or
fingerprint of the intended wallet supplies an independent comparison. An address searched over a
limited range can fail to match because the correct path lies outside that range.

The creation check covers the words the program produced, not the copy you wrote down. It detects
a difference during that check; passing does not rule out all hardware faults. Rehearse from your
finished backup with [`mhfe check`](../README.md#mhfe-check).

## The optional wallet check

`mhfe new` can draw a new 24-word phrase that passes **MHFE-WALLET-CHECK-SEED-1** with a nonempty
BIP39 passphrase. The check is a 16-bit filter over the BIP39 seed of the phrase and passphrase.
It takes about 65,536 sequential trials on average, leaving about 240 of the phrase's 256 bits.
The [API reference](API.md#wallet-check-and-new-phrases) gives the digest and published examples;
the specification defines the
[draft profile](https://github.com/hobby-eng/mhfe-spec#optional-source-profile-a-recovery-check-for-new-24-word-phrases).

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
for a uniformly random original seed phrase do not by themselves cover this filtered draw.

The draw counter and elapsed duration are not retained in the summary: the proof assumes a draw
that reveals neither. This profile applies to new wallets only; keep a compatible program with
the backup.

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

Anyone who can read the container can spend funds in its wallet without a BIP39 passphrase. A
container used directly as a decoy fools only someone who does not know MHFE was used. Enter it
only into a wallet you trust: a stored copy also lets its holder try MHFE passwords offline. If you
prepare a decoy passphrase for that wallet, whoever receives both can spend its funds; keep that
amount within what you can afford to lose.

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
specification's model and the wallet data available to the guesser.

The [README's recovery section](../README.md#several-passwords-and-hidden-wallets) explains how to
open several readings and the records or transfers that can expose hidden wallets. Rekeying moves
only the confirmed original seed phrase. Other wallets remain tied to the old container and
settings.

## Repair-card limits

The optional [MHFE-REPAIR-1
profile](https://github.com/hobby-eng/mhfe-spec#optional-repair-words-mhfe-repair-1) uses
Reed–Solomon parity over the word indexes. With `k` repair words it can repair `s` unreadable words
and `e` wrong words when `2e + s <= k`. It needs no password or Argon2 computation.

Beyond that bound, or with a card from another container, repair can fail or produce a different
checksum-valid container. A successful decode therefore does not confirm the backup or wallet.

The card alone also narrows the possible containers. In the idealized checksum model, eight repair
words leave roughly `2^168` checksum-valid candidates for a 24-word container, but roughly `2^40`
for a 12-word one. These counts do not identify the intended container or bypass its MHFE password.
They do make the card a partial copy of the container; give it the same protection and keep it
apart from the backup.
