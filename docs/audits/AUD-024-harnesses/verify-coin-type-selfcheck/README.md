# AUD-024 verify-coin-type-selfcheck harness

Audit AUD-024, role verify-coin-type-selfcheck (an adversarial verifier), reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1` (branch aud023-remediation).

## What it checks

Whether the runtime self-checks notice a wrong search root of the address check. The address
check of a coin searches the roots that `Address::search_roots` gives (`src/wallet.rs`), from the
coin's SLIP-44 coin types (`Coin::coin_types`), the address type's purpose (`AddressType::purpose`),
and, for Dash Platform, hardened chains (`find_address_until`). The runtime self-checks are the
`addresses` check (`src/wallet/known_answers/addresses.rs`) and the `address-search` check
(`src/wallet/known_answers.rs`), run at startup and in the full self-test.

`mutations.sh` extracts the crate at a revision (default `HEAD`) into a temporary folder. For each
mutation of `src/wallet.rs` it runs these library tests:

- `every_set_passes_at_startup`, which runs the repair, passwords, wallet and native startup sets;
- `the_address_check_passes`, the `addresses` check at both tiers;
- `the_address_search_is_stated_as_known`, the `address-search` check at both tiers.

As a control it then runs the unit test `addresses_are_found_where_their_wallets_put_them`, which
searches every row of the address table. It must fail, or the mutation did not take.

The mutations are Litecoin's coin type 2 to 3, Ethereum's and Injective's 60 to 61, XRP's 144 to
145, the nested SegWit purpose 49 to 48, the Taproot purpose 86 to 85, and DIP17 chains left
unhardened in the search loop. Dash's coin type 5 to 6 is a control that the `address-search` check
notices, through its Dash Platform case.

No Argon2 runs. The address check uses only the public BIP39 test phrase "abandon ... about".

## Inputs

The repository at the revision, through `git archive`. Cargo runs `--locked --offline` and needs
the crates in the local registry. `CARGO_TARGET_DIR` names the build folder, or a folder under
`TMPDIR` is used. The temporary copy is removed at exit.

## Command

From the repository root:

```sh
CARGO_TARGET_DIR=<a build folder outside target/> \
  docs/audits/AUD-024-harnesses/verify-coin-type-selfcheck/mutations.sh
```

## Expected output

At b6fca69, while the defect is present, the script prints the lines below and exits 1.

```text
FAIL: litecoin coin type 2 -> 3: every self-check passes; only the unit test fails
FAIL: ethereum and injective coin type 60 -> 61: every self-check passes; only the unit test fails
FAIL: xrp coin type 144 -> 145: every self-check passes; only the unit test fails
FAIL: nested SegWit purpose 49 -> 48: every self-check passes; only the unit test fails
FAIL: Taproot purpose 86 -> 85: every self-check passes; only the unit test fails
FAIL: DIP17 chains not hardened in the search loop: every self-check passes; only the unit test fails
PASS: dash coin type 5 -> 6 (control: noticed): noticed by every_set_passes_at_startup the_address_search_is_stated_as_known
```

Once a self-check covers every search root, every line reads PASS and the exit is 0. An exit of 2
means that a mutation did not apply or did not take.
