# Preparing and signing a release

The branch CI must pass for the exact release commit, including Linux, Windows, macOS and the
Chromium/Firefox browser checks. The tag workflow then builds the four canonical Docker archives,
builds both macOS archives, audits dependencies and replays every full-cost suite 3 and suite 4
vector with the native and independent implementations. It creates a draft only after those jobs
pass. Finish the draft locally so the OpenPGP private key never enters GitHub Actions.

Before tagging, publish curated notes in `docs/releases/v<version>.md`, check all new commit
signatures and create a signed annotated tag matching `Cargo.toml`. Run the repository's
`scripts/check.sh` and a cached/uncached canonical comparison locally; keep heavy builds sequential.
The long vector replays run in the release workflow rather than being duplicated locally.

## Sign the downloaded files

Download the complete draft into a fresh ignored folder, for example
`canonical-output-signing-v0.5.0/`. Verify the six archive hashes in `SHA256SUMS`, the GitHub build
attestations and the four canonical archives against the independent local Docker outputs before
signing. The maintainer's OpenPGP signing fingerprint is:

```text
28FC51B1DB80DF2101128CB30EDD4814591DD095
```

From that download folder:

```sh
sha256sum --check --strict SHA256SUMS
gpg --local-user 28FC51B1DB80DF2101128CB30EDD4814591DD095 --armor --detach-sign SHA256SUMS
gpg --verify SHA256SUMS.asc SHA256SUMS
gpg --armor --output RELEASE-SIGNING-KEY.asc --export 28FC51B1DB80DF2101128CB30EDD4814591DD095
```

Enter any key passphrase through GnuPG's local prompt. Upload `SHA256SUMS.asc` and the public
`RELEASE-SIGNING-KEY.asc` to the draft, then publish it. Keep Git commit/tag signing configured as
it already is; an OpenPGP signature of the files is separate from their SSH-signed Git history.

## Verify a downloaded release

Obtain the public key, compare its full fingerprint with the value above through a trusted source,
and import it with `gpg --import RELEASE-SIGNING-KEY.asc`. Then run:

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

`--ignore-missing` lets the check pass when only some archives were downloaded. The public key can
also be compared with the one GitHub publishes for the maintainer at
`https://github.com/hobby-eng.gpg`.

A valid signature establishes which key signed the checksum file. Its identity still depends on
checking the fingerprint; downloading a key beside an archive alone does not establish trust.
GitHub's build attestations additionally bind each archive to the source revision and workflow.
