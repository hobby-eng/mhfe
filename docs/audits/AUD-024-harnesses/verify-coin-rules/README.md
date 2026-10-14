# New coin touches (AUD-024, commit b6fca69)

Checks the claim that a coin's rules are spread over several dispatch sites (CORE-06, CORE-11):
it adds one variant `Probe` to `enum Coin` in a scratch copy of the tracked tree and counts the
places where `cargo check` reports a non-exhaustive match (E0004) for it. It also prints, for
information, the coin-specific sites the compiler does not point at (the hand-kept `Coin::ALL`,
`Address::type_description`, the guarded arms of `encodings::parse`, the human-readable parts of
`parse_segwit` and the alphabet choice of `parse_base58`). A pass shows only that the compiler
points at one place; it does not prove that no unforced site remains.

Inputs: the tracked tree at the given revision (default `HEAD`), extracted with `git archive`
into `../tmp/aud024/verify-coin-rules/harness-crate` (override with `AUD024_SCRATCH`); Cargo with
the locked dependencies available offline; `CARGO_TARGET_DIR` (default `../tmp/aud024/target`).
It writes nothing in the repository.

Command, from the repository root:

    docs/audits/AUD-024-harnesses/verify-coin-rules/new-coin-touches.sh b6fca69

Expected output at b6fca69: five places (src/wallet.rs:109, :127, :145, :164 and
src/wallet/encodings.rs:153), the informational list, then `FAIL: a new coin must grow a case in 5
places`, exit 1. Exit 0 means one place; exit 2 a setup failure.
