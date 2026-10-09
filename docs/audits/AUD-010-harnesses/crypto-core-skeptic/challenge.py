#!/usr/bin/env python3
"""AUD-010 crypto-core skeptic: tries to refute the two crypto-core findings independently.

Finding "wallet check on short readings and an empty passphrase":
  - recomputes, without the reviewer's scripts, the MHFE-WALLET-CHECK-SEED-1 digest T of the 12-word
    original of the published vector zero-12 with the reviewer's public passphrase P, once with
    BE32(128) (what wallet_check::phrase_passes computes for a 12-word phrase) and once with the
    profile's BE32(256);
  - reads the 24-word reading of zero-12's packed state (the state a correct recovery gives) and
    evaluates the profile on it with P: the specification's answer for this input;
  - asks the reviewed library (the crypto-core probe binary) phrase_passes and verify for P;
  - checks in the source that the rehearsal compares every reading for Reference::WalletCheck, that
    the CLI reads the wallet-check passphrase with "Enter if it has none", and that the empty
    passphrase is refused for a check only in the WebAssembly binding.
Finding "fingerprint and address search read the phrase strictly":
  - asks the probe for read_phrase and master_fingerprint on canonical, upper-case and four-letter
    forms of the BIP84 test phrase;
  - lists the callers of master_fingerprint and find_address that pass text not produced by the
    library itself.

Every check states what the finding claims; a FAIL line means the claim did not hold, and the exit
code is then 1. Public test data only.

    python3 challenge.py [--probe PATH]
"""

import hashlib
import json
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
REGISTRY = ROOT.parent / "workingspace/cargo/registry/src"
DEFAULT_PROBE = (
    ROOT.parent / "tmp/claude/aud010-crypto-core/probe-build/target/debug/aud010-crypto-core-probe"
)
TAG = b"MHFE-WALLET-CHECK-SEED-1"
P = "aud010 public probe 11656"
ABANDON = " ".join(["abandon"] * 11 + ["about"])
FAILURES = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'} {name}{': ' + detail if detail else ''}")
    if not ok:
        FAILURES.append(name)


def wordlist():
    # The English list of the bip39 3.0.0 crate that mhfe's Cargo.lock pins.
    source = next(REGISTRY.glob("*/bip39-3.0.0/src/language/english.rs")).read_text()
    words = re.findall(r'"([a-z]+)"', source)
    assert len(words) == 2048
    return words


def mnemonic(entropy, words):
    bits = len(entropy) * 8
    checksum = hashlib.sha256(entropy).digest()
    number = (int.from_bytes(entropy, "big") << (bits // 32)) | (checksum[0] >> (8 - bits // 32))
    count = (bits + bits // 32) // 11
    return " ".join(words[(number >> (11 * (count - 1 - i))) & 0x7FF] for i in range(count))


def seed(phrase, passphrase):
    return hashlib.pbkdf2_hmac(
        "sha512",
        unicodedata.normalize("NFKD", phrase).encode(),
        ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode(),
        2048,
        64,
    )


def digest(bits, phrase, passphrase):
    return hashlib.sha256(TAG + bits.to_bytes(4, "big") + seed(phrase, passphrase)).digest()


def ask_probe(binary, requests):
    lines = [" ".join([op] + [a.encode().hex() if a else "-" for a in args]) for op, *args in requests]
    out = subprocess.run([str(binary)], input="\n".join(lines) + "\n", capture_output=True, text=True, check=True)
    return [line.split(" ", 1)[1] for line in out.stdout.splitlines()]


def wallet_check_finding(words, binary):
    t128 = digest(128, ABANDON, P)
    t256 = digest(256, ABANDON, P)
    check("F1 T(BE32(128), zero-12 original, P) starts with 16 zero bits", t128[:2] == b"\0\0", t128.hex())
    check("F1 T(BE32(256), zero-12 original, P) does not", t256[:2] != b"\0\0", t256.hex())

    vector = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())
    state = bytes.fromhex(vector["packing"]["state_hex"])
    reading24 = mnemonic(state, words)
    check("F1 zero-12 short reading is the 12-word original", mnemonic(state[:16], words) == ABANDON)
    t24 = digest(256, reading24, P)
    check(
        "F1 profile answer for zero-12 + P (24-word reading, BE32(256)) is 'does not match'",
        t24[:2] != b"\0\0",
        t24.hex(),
    )

    answers = ask_probe(binary, [("wcpass", ABANDON, P), ("wcverify", ABANDON, P), ("wcpass", reading24, P)])
    check("F1 library phrase_passes(12-word original, P) = true", answers[0] == "OK true", answers[0])
    check("F1 library verify(12-word original, P) refuses", answers[1] == "ERR INVALID_WORD_COUNT", answers[1])
    check("F1 library phrase_passes(24-word reading, P) = false", answers[2] == "OK false", answers[2])

    rehearsal = (ROOT / "src/rehearsal.rs").read_text()
    arm = re.search(
        r"\| Reference::WalletCheck \{ \.\. \} => \{.*?matching_short_lengths\(&x\)\.into_iter\(\)\.chain\(\[24\]\)",
        rehearsal,
        re.S,
    )
    check("F1 compare_state compares every reading of X for WalletCheck, short ones first", arm is not None)
    compare = re.search(r"Reference::WalletCheck \{ passphrase \} => Ok\(CheckOutcome::of\(wallet_check::phrase_passes\(", rehearsal)
    check("F1 compare() uses phrase_passes (no length or passphrase rule)", compare is not None)
    to_check = re.search(r"fn recover_to_check.*?\n    \}\n", rehearsal, re.S).group(0)
    check("F1 recover_to_check has no empty-passphrase refusal", "is_empty" not in to_check)

    cli = (ROOT / "src/bin/mhfe/check.rs").read_text()
    branch = re.search(r"Choice::WalletCheck => \{\s*//[^\n]*\n\s*check_passphrase = read_passphrase\(", cli)
    check("F1 CLI reads the wallet-check passphrase with read_passphrase (Enter for none)", branch is not None)
    core = (ROOT / "src/wasm_api/core.rs").read_text()
    check(
        "F1 browser binding refuses an empty wallet-check passphrase itself",
        "if wallet.wallet_check && passphrase.is_empty()" in core,
    )
    check(
        "F1 browser decrypt still reports the empty-passphrase form",
        "candidate.passes_wallet_check_without_passphrase()" in core,
    )


def fingerprint_finding(binary):
    upper = ABANDON.upper()
    prefixes = " ".join(w[:4] for w in ABANDON.split())
    # Fullwidth Latin letters (U+FF41..), which NFKD maps to ASCII: the opposite direction.
    fullwidth = "".join(chr(ord(c) + 0xFEE0) if "a" <= c <= "z" else c for c in ABANDON)
    answers = ask_probe(
        binary,
        [
            ("fp", ABANDON, ""),
            ("fp", upper, ""),
            ("fp", prefixes, ""),
            ("read", upper),
            ("read", prefixes),
            ("fp", fullwidth, ""),
            ("read", fullwidth),
        ],
    )
    check("F2 master_fingerprint(canonical) = 73c5da0a", answers[0] == "OK 73c5da0a", answers[0])
    check("F2 master_fingerprint(capitals) refuses", answers[1] == "ERR INVALID_PHRASE", answers[1])
    check("F2 master_fingerprint(four-letter) refuses", answers[2] == "ERR INVALID_PHRASE", answers[2])
    check("F2 read_phrase(capitals) accepts", answers[3] == "OK " + ABANDON, answers[3])
    check("F2 read_phrase(four-letter) accepts", answers[4] == "OK " + ABANDON, answers[4])
    # Two reading rules, both ways; neither gives another wallet, only a refusal.
    check("F2 master_fingerprint(fullwidth) accepts after NFKD", answers[5] == "OK 73c5da0a", answers[5])
    check("F2 read_phrase(fullwidth) refuses", answers[6] == "ERR INVALID_PHRASE", answers[6])

    callers = subprocess.run(
        ["grep", "-rn", r"master_fingerprint(\|find_address(", "src", "--include=*.rs"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    outside = [
        line
        for line in callers
        if not line.startswith(("src/wallet.rs", "src/wallet/known_answers.rs"))
        and "fn " not in line
    ]
    for line in outside:
        print(f"  caller: {line.strip()}")
    # Reviewed by hand: every caller below passes text the library wrote itself (a recovered or
    # new phrase, a container from encrypt, repair or ContainerFacts, all canonical), or a test
    # constant. The one exception is the browser binding walletFingerprint, which passes the
    # page's `phrase` as given.
    library_text = (
        "src/rehearsal.rs:298:",  # recovered reading (read_phrase / phrase_from_entropy)
        "src/rehearsal.rs:307:",  # recovered reading
        "src/rehearsal.rs:386:",  # test constant
        "src/rehearsal.rs:650:",  # test constant
        "src/rekey.rs:490:",  # test constant
        "src/wasm_api/wallet.rs:132:",  # NewPhrase from PhraseDraw
        "src/wasm_api/repair.rs:106:",  # repaired container, written from word indexes
        "src/wasm_api/core.rs:238:",  # sealed container
        "src/wasm_api/core.rs:379:",  # decrypt candidate
        "src/wasm_api/core.rs:695:",  # rekey recovered phrase
        "src/wasm_api/core.rs:850:",  # hidden wallet phrase
        "src/wasm_api/core.rs:1085:",  # container from encrypt (on_unverified)
        "src/bin/mhfe/terminal.rs:389:",  # print_phrase of decrypt/encrypt/new/repair/rekey/wallets output
        "src/container.rs:128:",  # ContainerFacts.words, canonical
    )
    page_text = [line for line in outside if not line.startswith(library_text)]
    for line in page_text:
        print(f"  passes text it did not write: {line.strip()}")
    check(
        "F2 only MhfeWallet.fingerprint (wasm_api/wallet.rs:64) passes caller-supplied text",
        len(page_text) == 1 and page_text[0].startswith("src/wasm_api/wallet.rs:64:"),
    )


def main(arguments):
    binary = Path(arguments[1]) if arguments[:1] == ["--probe"] else DEFAULT_PROBE
    words = wordlist()
    wallet_check_finding(words, binary)
    fingerprint_finding(binary)
    print(f"{len(FAILURES)} failed" + (": " + ", ".join(FAILURES) if FAILURES else ""))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
