# AUD-024 verifier harness: chosen-word reader against the phrase reader

Audit AUD-024, commit b6fca69 (branch aud023-remediation). Verifies the candidate finding that
`word_wishes::number_of` (src/word_wishes.rs:254-261) reads a typed word with Unicode
`to_lowercase`, while the library's phrase reader (src/phrase.rs:51-53, 205) uses ASCII lower case,
so U+212A KELVIN SIGN + "ite" is accepted as the chosen word or word never to use "kite" but
refused as word 1 of a phrase.

Inputs: public data only, the English BIP39 words "kite", "abandon", "abuse" and a few others, and
the U+212A character. No Argon2 runs.

What it checks:

1. Lists every non-ASCII Unicode scalar value whose Rust `to_lowercase` is ASCII (only U+212A).
2. For "kite", "KITE", "Kite", "\u{212A}ite" and "\u{212A}ITE": `WordWishes::new` as a chosen word
   and as a word never to use, `WordWishes::new` with the token chosen and "kite" never to use (a
   refusal "also a word never to use" proves it resolved to kite), and `check_phrase` /
   `read_phrase` of the valid phrase "kite abandon x10 abuse" with the token as word 1.
3. Unicode whitespace around a word, which both readers accept.

Command, from the repository root:

    CARGO_TARGET_DIR=<scratch>/target cargo run --offline --quiet \
      --manifest-path docs/audits/AUD-024-harnesses/verify-kelvin-chosen-word/Cargo.toml

Expected output at b6fca69: the two U+212A cases print "-> DISAGREE", the last line is
"disagreements: 2" and the exit code is 1. After a fix that reads chosen words with the phrase
reader's rule, every case agrees, the last line is "disagreements: 0" and the exit code is 0.
