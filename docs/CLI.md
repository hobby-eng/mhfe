# Command-line reference

Use the [README menu](../README.md#menu) to choose a task. This guide covers terminal input,
wallet references, scripts and download checks. Run `mhfe <command> --help` for every option.

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
visible and requested output can stay in scrollback. New-wallet generation, extra-password
recovery and a rekey's visual confirmation require a private screen.

## Supported wallet references

`mhfe check`, rekey confirmation and searches can compare a phrase with a wallet address or master
key fingerprint. A fingerprint has 32 bits and does not offer the strength of a full address
comparison. They do not reveal the phrase. Keep references separate from the container: a reference
can help someone test password guesses.

Supported coins are Bitcoin, Ethereum and other EVM networks, XRP, Tron, Zcash transparent,
Dogecoin, Bitcoin Cash, Litecoin, Ethereum Classic, Cosmos, Injective and Dash. The Ethereum
encoding covers networks such as BNB Smart Chain, Polygon, Avalanche C-Chain, Arbitrum, Optimism and
Base; the address itself does not name the EVM network.

Dash supports Core `X…` addresses and Platform payment `dash1k…` addresses under DIP17,
`m/9'/5'/17'/account'/0'-1'/index`. Shielded Zcash `zs1…` and `u1…` addresses and Dash Orchard
`dash1z…` addresses are refused because their keys need different cryptography. Use that wallet's
transparent address instead.

The program identifies all supported coins whose address form matches. Shared forms include:

| Address form | Coins searched                |
| ------------ | ----------------------------- |
| `1…`         | Bitcoin and Bitcoin Cash      |
| `3…`         | Bitcoin and Litecoin          |
| `0x…`        | Ethereum and Ethereum Classic |

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

Secrets are never accepted as MHFE command arguments. Another program can supply them through a
pipe. On Linux with systemd 249 or later, for example:

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

For public test data only, you can supply literal text:

```bash
printf '%s\n%s\n%s\n' \
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' \
  'public test password' 'public test password' | mhfe encrypt --stdin
```

Never replace that example with real wallet material in a shell command. Typed commands can stay
in history, and external programs' arguments can appear in process listings.

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
gh attestation verify mhfe-v0.7.0-linux-x86_64.tar.gz --repo hobby-eng/mhfe
```

Use your archive's name in that command. For v0.3.0 to v0.5.0, attestations name commits preceding a
history rewrite; the [mapping record](releases/history-rewrite-2026-10-09.md) gives the
corresponding current commits.
