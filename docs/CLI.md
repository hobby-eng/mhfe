# Command-line reference

Use the [README menu](../README.md#menu) to choose a task. This guide covers terminal input,
wallet references, scripts and download checks. Run `mhfe <command> --help` for every option.

## Command examples

The examples follow the [main menu](../README.md#menu). Each command is a separate choice, not a
script to run from top to bottom. Options set non-secret choices; the program still prompts for
phrases, passwords, passphrases and references. Unless stated otherwise, these examples run in an
interactive terminal.

For a one-off recovery or backup, use the [recommended offline live-system
workflow](../README.md#getting-started). You do not need `--stdin` or `systemd-ask-password` for it.
The [script examples](#public-test-data-examples) show redirected input separately.

### 1. Encrypt

Start with a seed phrase you already have. The examples with `--same-length` require a 12-, 15-,
18- or 21-word original seed phrase.

```bash
# Choose settings, container format, repair words and password at the prompts.
mhfe encrypt

# Defaults stated explicitly, your own password and four repair words.
mhfe encrypt --pim 0 --mem 0 --new-password own --repair-words 4

# Five generated password words, without a repair card.
mhfe encrypt --pim 0 --mem 0 --new-password words --repair-words 0

# Five words plus a check word, six repair words and twice the default passes.
mhfe encrypt --pim 1 --mem 0 --new-password check-word --repair-words 6

# A generated character password and memory level 2 (4 GiB).
mhfe encrypt --pim 0 --mem 2 --new-password chars --repair-words 4

# Keep a shorter phrase's word count, with two repair words.
mhfe encrypt --pim 0 --mem 0 --same-length --repair-words 2

# Combine same-length format, PIM 3, 4 GiB and a generated check-word password.
mhfe encrypt --pim 3 --mem 2 --same-length \
  --new-password check-word --repair-words 8
```

At a terminal, omitting `--same-length` leaves the format question open; 24 words are its default.
For redirected input, see [the complete public-data example](#public-test-data-examples), which
also covers `encrypt --stdin`.

### 2. Decrypt

Use the settings that made the container. `--words` is the original phrase's length, not necessarily
the container's length.

```bash
# Choose the settings and enter the container and password.
mhfe decrypt

# Default settings, automatic length detection, no wallet BIP39 passphrase.
mhfe decrypt --pim 0 --mem 0 --words auto --passphrase-used no

# A container made with PIM 1 and memory level 1; prompt for its wallet passphrase.
mhfe decrypt --pim 1 --mem 1 --words auto --passphrase-used yes

# State a 12-word original length, including for a 12-word same-length container.
mhfe decrypt --pim 0 --mem 0 --words 12

# State 24 words and evaluate the optional check with the wallet passphrase.
mhfe decrypt --pim 0 --mem 0 --words 24 --passphrase-used yes

# Ask for the repair card immediately after the container.
mhfe decrypt --pim 0 --mem 0 --repair --words auto --passphrase-used no

# Without a card, search two marked missing words using the container's own address.
# Search its first account's first 100 receiving and 100 change addresses.
mhfe decrypt --pim 0 --mem 0 --scan-gap 100 --words auto --passphrase-used no
```

For several passwords or hidden wallets, run the first or automatic-detection example and choose
**Add another password** at the private prompt. Each extra password has its own settings. There
is no argument containing the passwords or their count. `--stdin` supports one password; examples
appear [below](#public-test-data-examples).

### 3. Check

An address or fingerprint is entered at a prompt, not after the option. Choose one reference kind:
`--address`, `--fingerprint` or `--words`.

```bash
# Choose what to compare with after entering the password and BIP39 passphrase.
mhfe check

# Use an address; determine possible coins from it.
mhfe check --pim 0 --mem 0 --address

# Limit an address check to Bitcoin and one known receiving path.
mhfe check --pim 0 --mem 0 --address --coin bitcoin --path "m/84'/0'/0'/0/5"

# A Bitcoin Taproot address on its first receiving path.
mhfe check --pim 0 --mem 0 --address --coin bitcoin --path "m/86'/0'/0'/0/0"

# A Dash Core address on its first receiving path.
mhfe check --pim 0 --mem 0 --address --coin dash --path "m/44'/5'/0'/0/0"

# A Dash Platform payment address on its first receiving path.
mhfe check --pim 0 --mem 0 --address --coin dash --path "m/9'/5'/17'/0'/0'/0"

# An Ethereum/EVM address on the usual first receiving path.
mhfe check --pim 0 --mem 0 --address --coin ethereum --path "m/44'/60'/0'/0/0"

# Compare the wallet's eight-hex-digit master key fingerprint instead.
mhfe check --pim 0 --mem 0 --fingerprint

# Check the built-in check bits for a stated shorter original length.
mhfe check --pim 0 --mem 0 --words 12

# Detect the original length and evaluate its own checks with the passphrase entered.
mhfe check --pim 0 --mem 0 --words auto

# Repair first, then check an address using the container's non-default settings.
mhfe check --pim 1 --mem 1 --repair --address

# Search marked missing words without a card, then compare with a fingerprint.
mhfe check --pim 0 --mem 0 --scan-gap 500 --fingerprint
```

The [format tables](#supported-wallet-references) list every supported coin and address family.
`--coin` selects the coin's identifier: `bitcoin`, `bitcoin-cash`, `cosmos`, `dash`, `dogecoin`,
`ethereum`, `ethereum-classic`, `injective`, `litecoin`, `tron`, `xrp` or `zcash`.
`--path` compares one address; without it the normal search range applies. `--scan-gap` affects the
preceding search for two missing container words, not that final address check. Fingerprints
provide a 32-bit comparison; a known address is the stronger reference.

### 4. Rekey

`--pim` and `--mem` describe the old container. `--new-pim` and `--new-mem` describe its
replacement. The password is changed at the prompts; `--new-password` chooses how that new password
is obtained.

```bash
# Ask for old settings, confirmation and the new container's choices.
mhfe rekey

# A 12-word original in a 24-word container: confirm by its unique built-in check.
mhfe rekey --pim 0 --mem 0 --words 12 --confirm check \
  --passphrase-used no --new-pim 0 --new-mem 0 \
  --new-password own --repair-words 4

# Detect the length, confirm by an address and use a generated five-word password.
mhfe rekey --pim 0 --mem 0 --words auto --confirm address \
  --passphrase-used no --new-pim 1 --new-mem 0 \
  --new-password words --repair-words 4

# A 24-word original with a BIP39 passphrase: confirm by fingerprint.
# Move from PIM 1 / 3 GiB to PIM 0 / 2 GiB, using a check-word password.
mhfe rekey --pim 1 --mem 1 --words 24 --confirm fingerprint \
  --passphrase-used yes --new-pim 0 --new-mem 0 \
  --new-password check-word --repair-words 8

# No address or fingerprint known: compare the phrase with your independent backup.
mhfe rekey --pim 0 --mem 0 --words 24 --confirm show \
  --passphrase-used no --new-pim 0 --new-mem 0 \
  --new-password chars --repair-words 0

# Repair the old container first; make a new card for the replacement.
mhfe rekey --pim 0 --mem 0 --repair --scan-gap 100 \
  --words auto --confirm address --passphrase-used yes \
  --new-pim 1 --new-mem 1 --new-password own --repair-words 6
```

`--confirm check` needs a stated 12- to 21-word original and a unique passing built-in check; it
does not apply to same-length containers. `--confirm show` requires an independent comparison and
a private screen, and is unavailable for some conflicting readings. `rekey` has no `--stdin`
mode. Its address confirmation detects the coin; it has no `--coin` or `--path` option.

Changing neither the password nor the settings is refused. The old container keeps working, and
other wallets derived from it do not move to the replacement. Rehearse the replacement with `check`.

### 5. Repair and repair words

For a card-based repair, type the container with `?` for unreadable words, then the repair card.
Without a card, leave that answer empty to see the available searches.

```bash
# Repair a container using its card, or choose a search when the card is missing.
mhfe repair

# Supply the settings needed if a missing-word search has to recover candidates.
mhfe repair --pim 1 --mem 1

# For two missing words, compare the container's own wallet over a larger gap.
mhfe repair --pim 0 --mem 0 --scan-gap 500

# Make a card for an existing container, with each supported repair-word count.
mhfe repair-words --count 2
mhfe repair-words --count 4
mhfe repair-words --count 6
mhfe repair-words --count 8
```

The last four commands are alternatives, not four parts of one card. Card-based repair and card
generation need no password or Argon2 work; the settings matter only for a search without a card.
The [public-data examples](#public-test-data-examples) cover `repair --stdin` and
`repair-words --stdin` too.

### 6. Password

```bash
# Five random words from the EFF list.
mhfe password

# Longer word passwords.
mhfe password --words 6
mhfe password --words 8

# Five random words and their computed sixth check word.
mhfe password --check-word

# Use real dice: five rolls from 1 to 6 for each word.
mhfe password --dice --words 6
mhfe password --dice --check-word

# Random characters: 16 by default, or the count you give.
mhfe password --chars
mhfe password --chars 24
```

The menu's Password entry makes another password of the same kind each time you press Enter.

Word counts range from 1 to 32 and character counts from 1 to 64. `--check-word` always makes five
random words and their check word, so it cannot be combined with `--words` or `--chars`.
`--chars` also cannot be combined with `--dice`. The check word adds no password strength.

### 7. Self-test

```bash
# Known answers and the slower component checks, up to 256 MiB.
mhfe self-test

# Also test a 24-word and a same-length container at their published full cost.
mhfe self-test --vectors
```

The second command takes minutes and 2 GiB; run it when you intend to perform that full-size test.
`check` rehearses your own backup, while `self-test` checks the program with public data.

### 8. Help and version

```bash
mhfe --help
mhfe encrypt -h
mhfe encrypt --help
mhfe help rekey
mhfe --version
```

`-h` gives the short help; `--help` gives the detailed help. Substitute any command name for
`encrypt` to inspect its options.

### Quit

Run `mhfe` to open the menu, then choose **Quit** or press Escape or q. A running command is
cancelled with the keys in [Terminal input and cancellation](#terminal-input-and-cancellation).
There is no separate `mhfe quit` command.

### Browser fast mode

This is an extra first menu entry when a page and its checksum file are beside the program.

```bash
# Serve and open a verified local HTML file.
mhfe serve tool.html

# Print the local URL so you can open it yourself.
mhfe serve tool.html --no-browser

# A path containing spaces.
mhfe serve "./offline wallet/tool.html" --no-browser
```

The matching `mhfe-fast-mode.sha256` must be beside the HTML file. Stop the server with Ctrl+C.
The [browser guide](BROWSER-PACKAGE.md#fast-and-standard-mode) covers the Python alternative and
required headers.

### Public test-data examples

These Bash examples use the specification's [`zero-12`
vector](https://github.com/hobby-eng/mhfe-spec/blob/v0.7.0/vectors/suite3/zero-12.json) and its
[repair
card](https://github.com/hobby-eng/mhfe-spec/blob/v0.7.0/vectors/profiles/repair-words.json). All
phrases, passwords and references below are public. Never fund these wallets or substitute real
wallet material in shell literals. These examples are for testing the script interface; interactive
prompts are the recommended way to enter your own material.

Each encryption or recovery still costs the real 2 GiB and minutes of work. Repair and making
repair words do not. Set up the public inputs once in Bash:

```bash
test_phrase='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
test_password='public test password'
test_container='donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve cycle famous provide heart ahead chunk caution peace'
test_card='shaft pupil patient jewel'
test_damaged='donate stove ? picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve ? famous provide heart ahead chunk caution peace'
```

Encrypt the phrase, requesting its four-word card. The output is `test_container` on the first
line and `test_card` on the second:

```bash
printf '%s\n' "$test_phrase" "$test_password" "$test_password" |
  mhfe encrypt --stdin --pim 0 --mem 0 --new-password own --repair-words 4
```

Recover the published container; the output is `12 verified` followed by `test_phrase`:

```bash
printf '%s\n' "$test_container" "$test_password" |
  mhfe decrypt --stdin --pim 0 --mem 0 --words auto --passphrase-used no
```

Rehearse its built-in check, then its master fingerprint and its first native SegWit address.
The empty input line before each wallet reference means no BIP39 passphrase. Each check matches:

```bash
printf '%s\n' "$test_container" "$test_password" |
  mhfe check --stdin --pim 0 --mem 0 --words 12

printf '%s\n' "$test_container" "$test_password" '' '73c5da0a' |
  mhfe check --stdin --pim 0 --mem 0 --fingerprint

printf '%s\n' "$test_container" "$test_password" '' \
  'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu' |
  mhfe check --stdin --pim 0 --mem 0 --address --coin bitcoin --path "m/84'/0'/0'/0/0"
```

Restore missing words 3 and 17 from the public card, or generate that card again:

```bash
printf '%s\n' "$test_damaged" "$test_card" |
  mhfe repair --stdin

printf '%s\n' "$test_container" |
  mhfe repair-words --stdin --count 4
```

Repair while recovering or rehearsing. The card line comes immediately after the container:

```bash
printf '%s\n' "$test_damaged" "$test_card" "$test_password" |
  mhfe decrypt --stdin --repair --pim 0 --mem 0 --words 12

printf '%s\n' "$test_damaged" "$test_card" "$test_password" '' '73c5da0a' |
  mhfe check --stdin --repair --pim 0 --mem 0 --fingerprint
```

For [the same-length container
vector](https://github.com/hobby-eng/mhfe-spec/blob/v0.7.0/vectors/suite4/same-length-zero-12.json),
the same public phrase, password and settings give a 12-word container. Its recovery is unverified,
so use a wallet reference:

```bash
test_same_length='renew alert there knife dose allow fashion casino kiwi lens sister bless'

printf '%s\n' "$test_phrase" "$test_password" "$test_password" |
  mhfe encrypt --stdin --same-length --pim 0 --mem 0 --repair-words 0

printf '%s\n' "$test_same_length" "$test_password" |
  mhfe decrypt --stdin --pim 0 --mem 0 --words 12

printf '%s\n' "$test_same_length" "$test_password" '' '73c5da0a' |
  mhfe check --stdin --pim 0 --mem 0 --fingerprint
```

### Timing with public data

`test-benchmark` is a development command outside the menu. It times an encryption and recovery
using a public phrase and prints JSON; it needs no input secrets.

```bash
mhfe test-benchmark --pim 0 --mem 0
mhfe test-benchmark --pim 1 --mem 1
```

## Terminal input and cancellation

The menu and each command use arrow keys and Enter for choices; numbered answers can be selected
directly. A private screen shows secret input and output where the terminal supports it. Enter or
Escape closes a finished result screen after you have copied its words. It does not close a screen
while the operation is still running.

| Key or signal                 | Effect                                                    |
| ----------------------------- | --------------------------------------------------------- |
| Ctrl+C                        | Stop immediately, including inside a cipher round         |
| Escape or q at a list         | Cancel the current command                                |
| Ctrl+D at an empty prompt     | Cancel the current command                                |
| SIGTERM or a closed terminal  | Stop as for Ctrl+C                                        |
| Ctrl+\\ or Ctrl+Z during work | Stop as for Ctrl+C; at a prompt they are input characters |

Handled cancellation restores terminal settings and leaves the private screen. A standalone
cancelled command exits with 130. From the menu, Escape, q or Ctrl+D returns to the menu; Ctrl+C
ends the command and menu. Each command runs as a separate process. After a crash or kill, the
menu restores the terminal and reports that the command crashed or was killed.

BIP39 words accept case differences and four-letter prefixes. Tab completes them and Ctrl+W removes
the last word. Passwords preserve case, spaces and other characters for validation; controls such
as Tab are refused. Without a private screen, secret input has no echo, container input remains
visible and requested output can stay in scrollback. Recovery with extra passwords and a rekey's
visual confirmation require a private screen.

## Supported wallet references

`mhfe check`, rekey confirmation and searches can compare a phrase with a wallet address or master
key fingerprint. A fingerprint has 32 bits and does not offer the strength of a full address
comparison. They do not reveal the phrase. Keep references separate from the container: a reference
can help someone test password guesses.

The program checks the full address and searches every supported coin whose encoding matches.
The main-network formats are:

| Address form             | Coins searched                                    | Address type                   |
| ------------------------ | ------------------------------------------------- | ------------------------------ |
| `1…`                     | Bitcoin and Bitcoin Cash                          | Legacy P2PKH                   |
| `3…`                     | Bitcoin and Litecoin                              | Nested SegWit (BIP49)          |
| `bc1q…`                  | Bitcoin                                           | Native SegWit P2WPKH (BIP84)   |
| `bc1p…`                  | Bitcoin                                           | Taproot (BIP86)                |
| `bitcoincash:q…` or `q…` | Bitcoin Cash                                      | CashAddr P2PKH                 |
| `cosmos1…`               | Cosmos                                            | Cosmos account                 |
| `X…`                     | Dash                                              | Core P2PKH (BIP44)             |
| `dash1k…`                | Dash                                              | Platform payment (DIP17/DIP18) |
| `D…`                     | Dogecoin                                          | P2PKH                          |
| `0x…` or `0X…`           | Ethereum, other EVM networks and Ethereum Classic | Ethereum-style account         |
| `inj1…`                  | Injective                                         | Injective account              |
| `L…`                     | Litecoin                                          | Legacy P2PKH                   |
| `M…`                     | Litecoin                                          | Nested SegWit (BIP49)          |
| `ltc1q…`                 | Litecoin                                          | Native SegWit P2WPKH (BIP84)   |
| `T…`                     | Tron                                              | Tron account                   |
| `r…`                     | XRP                                               | Classic account                |
| `t1…`                    | Zcash                                             | Transparent P2PKH              |

Ethereum-style addresses also cover BNB Smart Chain, Polygon, Avalanche C-Chain, Arbitrum, Optimism,
Base and other EVM networks. The address alone does not identify the EVM network.

The following test-network formats are supported too:

| Address form | Network searched       | Address type                   |
| ------------ | ---------------------- | ------------------------------ |
| `m…` or `n…` | Bitcoin testnet/signet | Legacy P2PKH                   |
| `2…`         | Bitcoin testnet/signet | Nested SegWit (BIP49)          |
| `tb1q…`      | Bitcoin testnet/signet | Native SegWit P2WPKH (BIP84)   |
| `tb1p…`      | Bitcoin testnet/signet | Taproot (BIP86)                |
| `tdash1k…`   | Dash Platform testnet  | Platform payment (DIP17/DIP18) |

Dash Platform uses `m/9'/5'/17'/account'/0'-1'/index` on mainnet and coin type `1'` on testnet.
The checks derive single-key addresses. P2SH addresses (`3…`, `M…`, `2…`) are searched as nested
SegWit; the prefix cannot distinguish them from other scripts. Native SegWit accepts 20-byte P2WPKH
addresses, not P2WSH. Shielded Zcash addresses and Dash Orchard (`dash1z…`, `tdash1z…`) are refused
because their keys need different cryptography; use a supported transparent address of that wallet.

`--coin` limits the search to one coin. Normally MHFE searches accounts 0 to 9 and the first 100
receiving and change addresses on the standard paths for that address type. `--path` selects a
single derivation path. The screen describes the scope before searching. An address outside it can
remain unfound even with the right phrase.

With a BIP39 passphrase, `check` tries the wallet with it first, then the wallet without it. A match
of the latter confirms only the phrase, and the result says so. A reference from the wallet without
a passphrase also lets someone test MHFE passwords without guessing that passphrase; for funds
held under a passphrase, keep a reference from that wallet.

## For scripts

`--stdin` reads one answer per line when input is redirected. At a terminal it changes nothing, so
typed secrets still use the normal prompt. Supply non-secret choices as options; scripts cannot
answer interactive choice lists.

| Command                              | Input lines, in order                                                                                                                               | Standard output                                                 |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `encrypt`                            | Original seed phrase, password, password again                                                                                                      | Checked container; repair words on a second line when requested |
| `decrypt`                            | Container, password; with `--passphrase-used yes`, the original wallet's BIP39 passphrase for a 24-word container, unless `--words` states 12 to 21 | One line per reading: `<words> <verified\|unverified> <phrase>` |
| `check --address` or `--fingerprint` | Container, password, BIP39 passphrase (empty if none), reference                                                                                    | Check result; no phrase                                         |
| `check --words N`                    | Container, password                                                                                                                                 | Check result                                                    |
| `check --words auto`                 | Container, password, original wallet's BIP39 passphrase (empty if none)                                                                             | Check result                                                    |
| `repair`                             | Container, repair words; `?` for unreadable words in either                                                                                         | Repaired container, or nothing when unchanged                   |
| `repair-words --count N`             | Container                                                                                                                                           | Repair words                                                    |

With `--repair`, `decrypt` and `check` read the repair words immediately after the container, before
the password; repair details go to standard error. `encrypt` uses a 24-word container unless given
`--same-length`; `--repair-words N` selects its card. Its keep list names any wallet BIP39
passphrase.

`check --stdin` requires `--address`, `--fingerprint` or `--words` to choose the reference kind.
Without `--coin`, the address determines the possible coins. Multiple matching lengths and a match
without the supplied passphrase are reported on standard error. The multi-password terminal
dialogue of `decrypt` is not available in scripts.

### Optional password agent

If an existing Linux setup uses systemd 249 or later password agents, it can pass answers to MHFE
through a pipe. This is optional; use MHFE's own prompts for the recommended live-system workflow:

```bash
{
  systemd-ask-password --echo=no "Original seed phrase:"
  systemd-ask-password --echo=no "Password:"
  systemd-ask-password --echo=no "Repeat the password:"
} | mhfe encrypt --stdin
```

Do not add `--keyname` or `--accept-cached`: they retain answers in the kernel keyring after the
command ends. MHFE's own prompts need no password agent; use this only where such an agent is
already part of your setup.

For literal input, use the [complete public test-data examples](#public-test-data-examples).

## Exit codes

| Code | Meaning                                                   |
| ---- | --------------------------------------------------------- |
| 0    | Completed; for `check`, the recovery matches              |
| 1    | Internal error, failed self-test or failed creation check |
| 2    | Invalid input or option                                   |
| 3    | Recovery does not match or is not verified                |
| 4    | Not enough memory for the selected level                  |
| 130  | Cancelled                                                 |

A failed creation check publishes no container to a pipe or file. An interactive preview may
already have been shown; it remains unchecked and must not be relied on.

## Release files

Archives are provided for Linux x86-64 and ARM64, macOS Intel and Apple silicon, and Windows
x86-64. Each includes the program, launcher and licences. The browser package is a separate
archive. Native x86-64 builds select AVX2 only on processors that support it.

Download `SHA256SUMS`, its signature `SHA256SUMS.asc` and `RELEASE-SIGNING-KEY.asc` alongside your
archive. Signatures are provided from v0.5.0. Import the key only after comparing its full
fingerprint with the published value through a trusted source:

```text
28FC51B1DB80DF2101128CB30EDD4814591DD095
```

The fingerprint is also recorded in [Preparing a release](RELEASING.md), and the maintainer's
key is available at [GitHub](https://github.com/hobby-eng.gpg). A key downloaded beside an archive
alone does not establish its identity. After checking it:

```bash
gpg --import RELEASE-SIGNING-KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

`--ignore-missing` permits downloading only your chosen archives. Check that the output reports
that archive as OK; stop on a bad signature or a failed checksum.

Build attestations additionally bind an archive to the GitHub workflow and source commit. Verify
them on the connected download computer before carrying the files to an offline machine:

```bash
gh attestation verify mhfe-v0.8.0-linux-x86_64.tar.gz --repo hobby-eng/mhfe
```

Use your archive's name in that command. For v0.3.0 to v0.5.0, attestations name commits preceding a
history rewrite; the [mapping record](releases/history-rewrite-2026-10-09.md) gives the
corresponding current commits.
