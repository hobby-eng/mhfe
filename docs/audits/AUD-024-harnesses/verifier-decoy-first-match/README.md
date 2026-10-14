# AUD-024 verifier-decoy-first-match harness

Audit AUD-024, role verifier-decoy-first-match, reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1` (branch aud023-remediation).

## What it checks

A two-word search for the missing words of a container phrase, with the master key fingerprint of
the container's own wallet, must not give one of several matching candidates as the container
found. The 12-word container phrase `abandon` ×10 `? ?` has 262,144 checksum-valid candidates, and
two of them, `abandon` ×10 `amused buzz` and `abandon` ×10 `employ giraffe`, share the fingerprint
`02ba9d7a`. The owner's container is taken to be `… employ giraffe`.

1. `fingerprints.py` computes, without any mhfe code, the BIP39 checksum and the BIP32 master key
   fingerprint of both pairs `amused buzz`/`employ giraffe` (02ba9d7a) and `able ghost`/
   `best student` (a30a4e0f), and the expected number of colliding pairs and odds.
2. `probe/src/main.rs` calls `ContainerSearch::new("abandon … ? ?").search_decoy` with
   `Reference::Fingerprint { 02ba9d7a, "" }` and checks which container it returns.
3. `cli_search.py` drives `mhfe repair` in a pseudo-terminal at `TERM=dumb`: the container phrase
   with `? ?`, no repair words, "The container's own wallet", fingerprint `02ba9d7a`, no
   passphrase. It types Ctrl+C at "Use the found container phrase?", so nothing is used.

No Argon2 runs at suite cost: the search compares candidates as wallets (PBKDF2 and BIP32 only),
and `mhfe repair` runs only its startup known-answer checks. About one minute in a debug build.

## Inputs

Public test data only: the `abandon` phrase family. The BIP39 English list is read from the bip39
3.0.0 crate source that cargo already fetched (`BIP39_ENGLISH_RS` overrides its path). Needs cargo
with the crates fetched (`--offline`) and python3. `CARGO_TARGET_DIR` is honoured; its default is
`${TMPDIR:-/tmp}/aud024-verifier-decoy-target`.

## Running

From the repository root:

```sh
docs/audits/AUD-024-harnesses/verifier-decoy-first-match/run.sh
```

## Expected output at b6fca69

Exit 1. `fingerprints.py` prints `fingerprint 02ba9d7a` for both `amused buzz` and
`employ giraffe`, `a30a4e0f` for `able ghost` and `best student`, and 8.000 expected pairs. The
probe prints `search_decoy returned words [(11, "amused"), (12, "buzz")]` and
`returned container is NOT the owner's: amused buzz`, then `FAIL: library`. The command line shows
`Found container phrase, 12 words` with words 11 and 12 `amused` and `buzz`, the answer
`1. Use it (and write the found words on your copy)`, and `FAIL: command line`.

A fix must make the search name both matching candidates, or refuse to pick one, instead of
giving `amused buzz` as the container found. The probe and the driver check only that the wrong
container is not given as found; adjust their output checks to the fixed result's form.
