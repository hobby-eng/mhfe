# AUD-024 spec-parity harness

Audit AUD-024, role spec-parity, reviewed commit `b6fca69238344dd2525b06270ee6ff3b055e68c1` of
`mhfe`, against `mhfe_spec` at `79c69d5eedbea0398392f46d977c1d7c96111bca`.

`check-spec-parity.py` checks what a script can tell about the agreement of `mhfe` with its
specification:

1. Every file of the specification's `vectors/suite3/` and `vectors/suite4/` (their `README.md`
   aside) equals its copy under `tests/fixtures/` byte for byte (SHA-256), and the `SHA256SUMS`
   manifests of both repositories pass `sha256sum --check`.
2. The suite identifiers and the salt and mask domain strings in `src/suite.rs`, and the source-check
   tag in `src/wallet_check.rs`, are the strings the specification defines.
3. The browser package's `check()` result is documented as `web/client.d.ts` declares it: the
   package resolves to `outcome`, so `docs/API.md` and `docs/BROWSER-PACKAGE.md` must not document a
   `matches` field (finding of AUD-024 on the stale `check()` documentation).
4. Every `MhfeClient` method that `web/client.d.ts` declares is named as `client.<method>(` in
   `docs/API.md`.

Inputs: the `mhfe` working tree, and the specification repository at `../mhfe_spec`, or the folder
that the environment variable `MHFE_SPEC` names. Needs Python 3.8 or later and `sha256sum`; no
network, no build, no Argon2.

Command, from the repository root:

```sh
python3 docs/audits/AUD-024-harnesses/spec-parity/check-spec-parity.py
```

Expected output at `b6fca69`: 66 lines starting `ok`, then these three failures, and exit code 1:

```text
FAIL  docs/API.md: no `matches` field of check() documented (lines [775])
FAIL  docs/BROWSER-PACKAGE.md: no `matches` field of check() documented (lines [117, 122])
FAIL  docs/API.md names client.keepOldContainer()
3 check(s) failed
```

After the documentation is corrected, every line starts `ok`, the last line is
`0 check(s) failed` and the exit code is 0.
