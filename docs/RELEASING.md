# Preparing and signing a release

Release files are built in CI and signed locally. The OpenPGP private key never enters GitHub
Actions. User-facing download checks are in the [command-line guide](CLI.md#release-files).

## Before tagging

Write curated notes in `docs/releases/v<version>.md` from the draft in
`docs/releases/unreleased.md`. Check the signatures of all new commits. The tag must be signed and
annotated and named `v<version>` with the version of `Cargo.toml`; `release.yml` refuses any other.

Branch CI must pass for the exact release commit on Linux, Windows and macOS. Chrome and Firefox
checks run on a manual `ci.yml` run or a tag, so branch success alone does not establish browser
acceptance. Run the local checks and both canonical builds sequentially:

```sh
scripts/check.sh
scripts/build-reproducible.sh
REPRODUCIBLE_NO_CACHE=1 scripts/build-reproducible.sh canonical-output-uncached
```

Compare the outputs from the cached and uncached builds. The canonical wrapper requires swap to
be off before building; arrange that separately before starting it.

## What the tag workflow runs

The release workflow calls `ci.yml` again on the tagged commit, including `scripts/check.sh` and
the Windows and macOS terminal suites. It builds four canonical Docker archives and two macOS
archives, runs Chrome and Firefox against the canonical browser and Linux archives, and audits
dependencies. It creates a draft release only after those jobs pass, using the versioned notes.

A missing notes file stops the canonical job before its build; the other CI and macOS jobs can
still continue until completion or cancellation.

## Sign the downloaded files

Download the entire draft into a new ignored folder, such as `canonical-output-signing-v0.7.0/`.
Before signing, verify all six archive hashes in `SHA256SUMS`, their GitHub attestations and the
four canonical archives against the independent local Docker outputs.

The maintainer's OpenPGP signing fingerprint is:

```text
28FC51B1DB80DF2101128CB30EDD4814591DD095
```

From the download folder:

```sh
sha256sum --check --strict SHA256SUMS
gpg --local-user 28FC51B1DB80DF2101128CB30EDD4814591DD095 --armor --detach-sign SHA256SUMS
gpg --verify SHA256SUMS.asc SHA256SUMS
gpg --armor --output RELEASE-SIGNING-KEY.asc --export 28FC51B1DB80DF2101128CB30EDD4814591DD095
```

Enter the key's passphrase only in GnuPG's local prompt. Upload `SHA256SUMS.asc` and the public
`RELEASE-SIGNING-KEY.asc` to the draft, then publish it. File signatures are separate from the
repository's SSH-signed commits and tags; leave Git signing configured as it is.

## Verify a downloaded release

Follow the [download verification steps](CLI.md#release-files), including comparison of the full
key fingerprint through a trusted source. A valid signature identifies the signing key; trusting
that key's identity requires checking its fingerprint. GitHub attestations additionally identify
the source revision and workflow that produced an archive.
