# AUD-024 wallet-derivation harness

Audit AUD-024, role wallet-derivation, reviewed commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`.

What it checks: mhfe's wallet derivation and the recovery checks built on it (`src/wallet.rs` and
`src/wallet/`, `src/search.rs`, `src/rehearsal.rs`, `src/wasm_api/`), against an oracle that does
not use mhfe or its Rust dependencies.

- `oracle.py`: secp256k1, BIP32, BIP39 seeds, Keccak-256, Bech32/Bech32m, Base58Check, CashAddr and
  EIP-55 written from the specifications; Python's `hashlib` gives only SHA-2, HMAC, PBKDF2 and
  RIPEMD-160.
- `validate_oracle.py`: checks the oracle first against 186 literal published values: BIP32 test
  vectors 1 to 4 (every xprv and xpub), the 24 English BIP39 vectors, BIP84, BIP86, BIP49, the
  SLIP-0014 addresses, DIP-0017/DIP-0018, EIP-55's examples, the CashAddr specification example and
  Keccak-256 digests.
- `gen_cases.py`, `gen_wasm_cases.py`: write the cases. The published vectors, mhfe's own table of
  43 known-answer addresses recomputed by the oracle, 1,104 differential addresses over every coin,
  address type, phrase length (12 to 24 words) and passphrase form (empty, ASCII, NFKD-changing,
  U+FDFA), boundary paths at 2^31−1, hardened derivation from parents whose key starts with a zero
  byte, address parsing (BIP173/BIP350 valid and invalid lists, EIP-55, the CashAddr table, DIP-0018
  refusals, Base58Check versions), path and limit parsing, the stated search scopes, and the
  missing-word candidates and decoy searches.
- `probe/`: a Rust program that runs the cases through mhfe's public API (`probe/src/main.rs`),
  prints refusal messages and deep-path timings (`messages.rs`), and runs the threaded decoy search
  and the threaded wallet-check draw (`threads.rs`).
- `wasm_probe.mjs`: the browser package's wallet bindings that need no Argon2 (`walletFingerprint`,
  `describeAddress`, `searchCandidates`, `searchDecoy` for every coin and address type).
- `check_passphrase_probe.mjs`, `wallet_check_reference_probe.mjs`, `owner_answer_probe.mjs`: the
  browser package's `CheckSession` and `RekeySession` with a stand-in Argon2 object; the first
  refuses every full-cost round, the other two compute every call with Node's own Argon2id at 1 MiB
  and one pass (reduced cost, their containers valid for the stand-in only).

Inputs: public test data only, and the public reference documents that `run.sh` downloads once
(BIPs 32, 49, 84, 86, 173, 350 and the BIP39 English list from bitcoin/bips, trezor/python-mnemonic
`vectors.json`, SLIP-0014, DIP-0017, DIP-0018, ERC-55, the CashAddr specification), checked against
`refs.sha256`. Needs python3, node (with `crypto.argon2Sync`), cargo with Rust 1.99.0 and the
crates of `Cargo.lock` already fetched (`--offline`), `prlimit` from util-linux, and for the
browser cases the built `dist/` and `target/wasm-bindgen/` of this commit (`scripts/build-wasm.sh`).
No full-cost Argon2 runs.

## Running

From the repository root, with an optional work directory (default
`${TMPDIR:-/tmp}/aud024-wallet-derivation`); `CARGO_TARGET_DIR` is honoured:

```sh
docs/audits/AUD-024-harnesses/wallet-derivation/run.sh conformance [work dir]
docs/audits/AUD-024-harnesses/wallet-derivation/run.sh findings [work dir]
```

## Expected output at b6fca69

`conformance` exits 0 and ends with `1445 cases, 1445 passed, 0 failed` (native),
`decoy search: Ok(Some([(24, "art")]))`, `draw on every core: Ok(Some("fatigue"))` and
`85 cases, 85 passed, 0 failed` (browser package). The oracle reports `0 mismatches` for mhfe's
43-row address table.

`findings` exits 1 while AUD-024's wallet-derivation defects are present, each failing line naming
the behaviour its cited rule requires:

- `BIP32 depth is one byte: a path of depth 256 is refused`, `a path of depth 100000 is refused`
  and `wasm describeAddress refuses a path of depth 256` fail: any depth is accepted.
- `wasm searchCandidates names the word count of 23 words with ?` fails: the refusal says that no
  word is marked missing.
- `a passphrase beside { words: 12 } is refused before any round` (and 21) fails with
  `ARGON2_FAILED after 1 full-cost round call(s)`: the check goes on to its rounds; the contrast
  lines pass.
- `an owner's passphrase that the rehearsal does not use is refused` fails: a rekey whose owner
  confirms a verified 12-word reading after LENGTH_DIFFERS accepts `ownerAnswer(true, passphrase)`
  and drops the passphrase (rehearsal `builtInCheck`).
- `the wallet-check reference does not report "doesNotMatch" beside a verified 12-word reading`
  fails: `{ walletCheck: true }` gives `doesNotMatch` with `builtInCheck: 12` in its evidence.
- `the decoy search panics when a thread is refused` fails: under `prlimit --nproc=1` the search
  panics with `failed to spawn thread`, while the wallet-check draw under the same limit succeeds.
- `the documents name check()'s former matches field` fails, after grep lists docs/API.md and
  docs/BROWSER-PACKAGE.md lines.

Once all of them are fixed, `findings` exits 0.
