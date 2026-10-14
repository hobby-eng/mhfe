# verify-gives-costs-width

Audit AUD-024, verifier of the candidate "style::gives, style::costs and style::fact_before_work
write their text without wrapping it", at commit b6fca69.

Rule: CORE-36, "Running text wraps at 78 columns"; `style::TEXT_WIDTH` (src/bin/mhfe/style.rs:405-408).

## static_widths.py

Reads src/bin/mhfe/style.rs and reports whether `gives`, `costs`, `fact_before_work`, `ok` and
`fact_as` call a wrapping helper, then renders every `style::gives` and `style::costs` call of
src/bin/mhfe/length_choice.rs and src/bin/mhfe/new_wallet.rs ("  ✓ " or "  ! " and the text, with
the library constants substituted) and measures it. Input: the source tree.

    python3 -B docs/audits/AUD-024-harnesses/verify-gives-costs-width/static_widths.py .

Expected at b6fca69: exit 1; `gives`, `costs` and `fact_before_work` call no wrapping helper, and
length_choice.rs:82 renders at 79 columns. Exit 0 once every line fits in 78 columns.

## search_line_probe.sh

Runs `mhfe check --stdin --pim 0 --mem 0 --address --coin bitcoin --path <62-character path>` with
the public vector tests/fixtures/suite3-vectors/nonzero-24.json (container and password) and the
public BIP84 address of the "abandon ... about" phrase. Standard input ends where the BIP39
passphrase is asked, so the command is refused with exit code 2 before any Argon2 round (address
space capped at 1 GiB as a guard). It measures the "Search" fact written by
`style::fact_before_work`. Inputs: a built mhfe binary and the repository root.

    CARGO_TARGET_DIR=/home/user/Documents/bip_tools/tmp/aud024/target cargo build --locked --release --bin mhfe
    bash docs/audits/AUD-024-harnesses/verify-gives-costs-width/search_line_probe.sh /home/user/Documents/bip_tools/tmp/aud024/target/release/mhfe .

Expected at b6fca69: "exit code: 2", the line
"  Search     only m/2147483647'/2147483647'/2147483647'/2147483647'/2147483647/0" at 80 columns,
"OVER WIDTH" and exit 1. Exit 0 once the fact wraps (the path then starts on a line of its own at
column 14, 75 columns).

The container-length explanation (style::gives at length_choice.rs:82) is measured at a terminal by
docs/audits/AUD-024-harnesses/guide-cli-infra/explanation_width_probe.py.
