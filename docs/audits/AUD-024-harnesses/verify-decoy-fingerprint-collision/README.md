# AUD-024 verify-decoy-fingerprint-collision

Audit AUD-024, at commit b6fca69238344dd2525b06270ee6ff3b055e68c1. This harness checks the
candidate finding that a two-word decoy search with a master key fingerprint returns the first
candidate that matches and never looks for a second one. It reproduces the defect in a few
seconds. The larger harness `../gap-1-aud023-observations-under-current-guide/decoy.sh` lists all
8 colliding pairs and takes about 66 CPU minutes.

## What it checks

1. **The library** (`probe/src/main.rs`). The probe takes two pairs of 12-word phrases that share
   a master key fingerprint (no passphrase):
   - `abandon` ×10 `able ghost` and `abandon` ×10 `best student` (a30a4e0f);
   - `abandon` ×10 `amused buzz` and `abandon` ×10 `employ giraffe` (02ba9d7a).

   It confirms that both phrases of each pair are valid and share the fingerprint. Then it runs
   `ContainerSearch::new("abandon ×10 ? ?").search_decoy` with the fingerprint of the later phrase
   of each pair, which stands for the owner's container. It fails when the search returns the
   other phrase.
2. **The command-line tool** (`cli_found.py`). The script drives `mhfe decrypt --pim 0` on a
   pseudo-terminal. It uses the terminal suite's session (`scripts/terminal_suite`). It types
   `abandon` ×10 `? ?`, then Enter for no repair words. It answers "The container's own wallet",
   fingerprint `a30a4e0f` and no passphrase. It fails when the tool shows `able ghost` as the
   found container phrase, offers to use it, and says nothing about another match or about the
   fingerprint's strength. The script then chooses "Use it" and presses Ctrl+C at "Container
   password:". It types no password, so no Argon2 runs.

## Inputs

All data is public: phrases made of `abandon` ×10 and two more BIP39 words. The harness needs:

- cargo with Rust 1.99.0, with the crates already fetched (`--offline`);
- python3;
- an mhfe binary built from the commit, by default `target/release/mhfe`.

Nothing uses the network.

## Command

From the repository root:

```sh
CARGO_TARGET_DIR=/tmp/aud024-verify-decoy-target \
  docs/audits/AUD-024-harnesses/verify-decoy-fingerprint-collision/run.sh target/release/mhfe
```

## Expected output at b6fca69

The command exits with 1. The probe prints `equal: true` for both pairs. The searches return
`[(11, "able"), (12, "ghost")]` and `[(11, "amused"), (12, "buzz")]`, each with
`container is [...]: false`. The probe ends with:

```text
RESULT: 2 of 2 searches returned the earlier candidate, not the container whose fingerprint was given
```

The command-line part shows `Comparing 262144 candidates with the container's own wallet.` and,
when the search takes longer than 100 ms, `Compared <n> of 262144`. Then it shows
`Found container phrase, 12 words` with
`11. able` and `12. ghost`. Below that it shows `✓ Found word 11: able, word 12: ghost, with the
container's own wallet.` and the answer `Use it` with the note `and write the found words on your
copy`. It ends
with these two lines:

```text
offered the earlier candidate (able ghost) as the found container phrase: True
any word of a warning about another match or the fingerprint's strength: False
```

A fix passes when both parts pass, so the command exits with 0. In that case the search reports
both candidates, refuses to choose one, or warns. A fix that changes the return type of
`search_decoy` makes the probe fail to build (exit 2). The probe then has to be adapted to the new
API.

## After the fix of AUD-024-FUN001

The search now compares every candidate and refuses a reference that more than one matches, with
the code `SEVERAL_CANDIDATES_MATCH`. The probe takes that refusal as the fixed behaviour: it prints
`refused, 2 candidate container phrases match the reference, ...` for each pair and ends with
`RESULT: 0 of 2 searches returned the earlier candidate, ...`. The command-line part shows the
refusal after `Compared 262144 of 262144` and asks again what the person knows, so that it prints
`offered the earlier candidate (able ghost) as the found container phrase: False`. The command
then exits with 0. The probe compares the refusal's code as text, so it still builds at b6fca69,
where it gives the output above.
