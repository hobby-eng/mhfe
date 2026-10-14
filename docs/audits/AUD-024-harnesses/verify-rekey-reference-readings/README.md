# AUD-024 harness: rekey compares a wallet reference with every reading

Audit AUD-024, at commit b6fca69 (b6fca69238344dd2525b06270ee6ff3b055e68c1).

## What it checks

That `RecoveredForRekey::confirm` (src/rehearsal/reencryption.rs) compares an address or the
master key fingerprint with every reading of the recovered state, as the rehearsal check's
`compare_state` (src/rehearsal.rs) does and as docs/API.md, docs/BROWSER-PACKAGE.md, web/client.js
and the method's own rustdoc say. Two public-data cases, on reduced-cost containers (test-only
Argon2 engine, 256 KiB and one pass; no full-cost Argon2 runs):

- A: the 24-word phrase of entropy `0^16 || SHA-256(0^16)[..16]`, whose state also reads as the
  12-word "abandon ... about" (fingerprint b61c9f21). The rehearsal check with that fingerprint
  says "matches"; a rekey with the length detected must confirm the 24-word phrase with it.
- B: the published ambiguous-12-21 phrase (a 12-word phrase whose state passes the 21-word check
  too). With 21 words stated the built-in check is refused with AMBIGUOUS_LENGTH; the documents
  then say an address or the fingerprint compares every reading, so the 12-word phrase's own
  fingerprint must confirm it.

## Inputs

- The repository at the commit given (default b6fca69), exported with `git archive` into a
  scratch folder (default `../tmp/aud024/verify-rekey-reference-readings/harness-crate`, or
  `$AUD024_SCRATCH`). No tracked file is changed.
- probe.patch: one unit test, `aud024_verify_rekey_reference_readings`, added to
  src/rehearsal/reencryption.rs.
- A Rust toolchain that builds the crate offline (`../workingspace/cargo` is used when present).
  `CARGO_TARGET_DIR` defaults to `../tmp/aud024/target`.

## Command (from the repository root)

```sh
docs/audits/AUD-024-harnesses/verify-rekey-reference-readings/run.sh
```

## Expected output

At b6fca69 the harness exits 1. Its lines include:

```text
AUD024 A: rehearsal check (Mhfe::check) with the original's fingerprint: Matches { path: None }
AUD024 A: rekey confirm, length Detect, original's fingerprint: Err(REFERENCE_MISMATCH)
AUD024 A: rekey confirm, length 24 stated, original's fingerprint: Ok(words 24, verified false)
AUD024 A: Rekey::new(Detect).recover with the original's fingerprint: Err("REFERENCE_MISMATCH")
AUD024 B: rehearsal check with the original's fingerprint: Matches { path: None }
AUD024 B: rekey confirm, 21 stated, built-in check: Err(AMBIGUOUS_LENGTH)
AUD024 B: rekey confirm, length 21 stated, original's fingerprint: Err(REFERENCE_MISMATCH)
FAIL: expected: AUD024 A: rekey confirm, length Detect, original's fingerprint: Ok(words 24
FAIL: expected: AUD024 A: Rekey::new(Detect).recover with the original's fingerprint: Ok(24)
FAIL: expected: AUD024 B: rekey confirm, length 21 stated, original's fingerprint: Ok(words 12
```

With the defect fixed every expectation prints PASS and the harness exits 0.
