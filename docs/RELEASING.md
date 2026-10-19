# Preparing and signing a release

The branch CI, which runs the fast checks on Linux, Windows and macOS, must pass for the exact
release commit; run the Chromium/Firefox browser checks by hand (`ci.yml` through
workflow_dispatch) or locally before tagging. The tag workflow then runs the release checks on the
tagged commit (it calls `ci.yml`: `scripts/check.sh`, the Chromium/Firefox checks and the Windows
and macOS tests with their terminal suites), builds the four canonical Docker archives and both macOS
archives, audits dependencies, and creates a draft only once all of these jobs pass. Finish the
draft locally so the OpenPGP private key never enters GitHub Actions. The same tag starts the Test
vectors workflow on its own: it replays every full-cost suite 3 and suite 4 vector with the native
and independent implementations in about three hours, and its result shows on the tag and in the
README's badge; the draft does not wait for it.

Before tagging, publish curated notes in `docs/releases/v<version>.md`, check all new commit
signatures and create a signed annotated tag matching `Cargo.toml`. Run the repository's
`scripts/check.sh` and a cached/uncached canonical comparison locally; keep heavy builds sequential.
The long vector replays run on GitHub for the tag rather than being duplicated locally.

A manual `ci.yml` run also checks the canonical Windows GNU executable in a Windows
pseudo-console and builds both macOS packages without creating a release. The macOS acceptance
check verifies their actual architectures, extracted hardened signatures, build provenance and byte-identical repacking
after changing checkout modes and timestamps. Its unsigned control must fail. These native checks
require their respective runners; portable archive controls on Linux do not replace them.

Build and compare cached and uncached outputs in separate output folders, one after the other:

```sh
scripts/build-reproducible.sh canonical-output-cached
REPRODUCIBLE_NO_CACHE=1 scripts/build-reproducible.sh canonical-output-uncached
cmp canonical-output-cached/release/SHA256SUMS canonical-output-uncached/release/SHA256SUMS
```

Local prerequisites, including the Playwright browser installation and archive tools, are in
[DEVELOPMENT.md](DEVELOPMENT.md#checks). Attestation verification needs a GitHub CLI version
that provides `gh attestation verify` and its policy flags.

## Sign the downloaded files

Download the complete draft into a fresh ignored folder, for example
`canonical-output-signing-v0.5.0/`. Verify the six archive hashes in `SHA256SUMS`, the GitHub build
attestations and the four canonical archives against the independent local Docker outputs before
signing. The maintainer's OpenPGP signing fingerprint is:

```text
28FC51B1DB80DF2101128CB30EDD4814591DD095
```

For each archive, enforce the release workflow, its tag and hosted runners before signing:

```sh
gh attestation verify mhfe-v0.6.0-linux-x86_64.tar.gz --repo hobby-eng/mhfe \
  --signer-workflow hobby-eng/mhfe/.github/workflows/release.yml \
  --source-ref refs/tags/v0.6.0 --deny-self-hosted-runners
```

Replace the version and file for the draft being checked, and repeat for every archive.

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
Verify each downloaded archive with the command above, using that release's version. The
[GitHub CLI policy options](https://cli.github.com/manual/gh_attestation_verify) constrain the
signer workflow, source tag and runner; `--repo` alone does not impose those restrictions.
