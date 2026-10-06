#!/usr/bin/env python3
"""AUD-008 independent protocol arithmetic; never computes Argon2."""

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import struct
import sys
import unicodedata


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wordlist", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    spec = root.parent / "mhfe_spec"
    words = re.findall(r'"([a-z]+)"', args.wordlist.read_text())
    assert len(words) == 2048 and len(set(words)) == 2048
    indexes = {word: i for i, word in enumerate(words)}

    def encode(entropy):
        checksum_bits = len(entropy) // 4  # BIP39 CS = ENT/32.
        checksum = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
        bits = (int.from_bytes(entropy, "big") << checksum_bits) | checksum
        count = (8 * len(entropy) + checksum_bits) // 11
        return " ".join(words[(bits >> (11 * (count - 1 - i))) & 2047] for i in range(count))

    def decode(text):
        tokens = text.split()
        assert len(tokens) in [12, 15, 18, 21, 24]
        value = 0
        for token in tokens:
            value = (value << 11) | indexes[token]
        cs = len(tokens) // 3
        entropy = (value >> cs).to_bytes(len(tokens) // 3 * 4, "big")
        assert (value & ((1 << cs) - 1)) == hashlib.sha256(entropy).digest()[0] >> (8 - cs)
        assert encode(entropy) == " ".join(tokens)
        return entropy

    def packed(entropy):
        return entropy + hashlib.sha256(entropy).digest()[:32 - len(entropy)]

    def matches(state):
        return [n for n in [12, 15, 18, 21] if packed(state[:n // 3 * 4]) == state]

    def xor(a, b):
        assert len(a) == len(b)
        return bytes(x ^ y for x, y in zip(a, b))

    vectors = []
    round_count = 0
    fixture_hashes = {}
    for suite, label in [(3, "MHFE-BIP39-256-EXPERIMENTAL-3"),
                         (4, "MHFE-BIP39-LP-EXPERIMENTAL-4")]:
        folder = root / "tests" / "fixtures" / f"suite{suite}-vectors"
        for path in sorted(folder.glob("*.json")):
            vector = json.loads(path.read_text())
            if not isinstance(vector, dict) or "encryption" not in vector:
                continue
            assert vector["suite_id"] == label, path.name
            assert path.read_bytes() == (spec / "vectors" / f"suite{suite}" / path.name).read_bytes()
            fixture_hashes[str(path.relative_to(root))] = digest(path)
            inputs = vector["inputs"]
            entropy = decode(inputs["phrase"])
            password = inputs["password"]
            assert password.encode().hex() == inputs["password_utf8_hex"]
            # The retained vectors use characters whose decomposition is stable in this
            # Python database. This does not certify every Unicode 17 code point.
            assert unicodedata.normalize("NFKD", password).encode().hex() == inputs["password_nfkd_utf8_hex"]
            assert 1 <= len(bytes.fromhex(inputs["password_nfkd_utf8_hex"])) <= 1024
            pim, memory = inputs["pim"], inputs["memory_level"]
            assert 0 <= pim <= 1023 and 0 <= memory <= 21
            expected_cost = {"variant": "Argon2id", "version": 19,
                             "memory_kib": (2 + memory % 2) << (20 + memory // 2),
                             "passes": 12 * (pim + 1), "lanes": 4, "output_bytes": 32}
            assert vector["argon2"] == expected_cost, path.name
            if suite == 3:
                state = packed(entropy)
                packing = vector["packing"]
                assert packing["entropy_hex"] == entropy.hex()
                assert packing["verifier_hex"] == state[len(entropy):].hex()
                assert packing["state_hex"] == state.hex()
                assert packing["words"] == len(inputs["phrase"].split())
                half = 16
            else:
                assert len(entropy) in [16, 20, 24, 28]
                state = entropy
                half = len(entropy) // 2
                assert vector["state"] == {"words": len(inputs["phrase"].split()),
                                           "entropy_bits": 8 * len(entropy), "half_bytes": half,
                                           "state_hex": entropy.hex()}
            encrypted = decode(vector["container"])
            assert len(encrypted) == len(state)
            assert encrypted != state  # Required fixed-point rejection.
            for direction, start, finish in [("encryption", state, encrypted),
                                               ("decryption", encrypted, state)]:
                trace = vector[direction]
                assert trace["input_state_hex"] == start.hex()
                assert trace["output_state_hex"] == finish.hex()
                rounds = trace["rounds"]
                assert len(rounds) == 12
                assert [r["round"] for r in rounds] == (list(range(12)) if direction == "encryption" else list(range(11, -1, -1)))
                current = start
                for r in rounds:
                    left, right = current[:half], current[half:]
                    assert r["left_before_hex"] == left.hex()
                    assert r["right_before_hex"] == right.hex()
                    argument = right if direction == "encryption" else left
                    message = struct.pack(">II", memory, pim)
                    if suite == 4:
                        message += struct.pack(">I", 8 * len(entropy))
                    message += struct.pack(">I", r["round"]) + argument
                    salt_input = (label + "/ROUND-SALT").encode() + message
                    mask_input = (label + "/ROUND-MASK").encode() + message
                    assert r["salt_input_hex"] == salt_input.hex()
                    assert r["mask_input_hex"] == mask_input.hex()
                    assert r["salt_hex"] == hashlib.blake2b(salt_input, digest_size=32).digest()[:16].hex()
                    key = bytes.fromhex(r["argon2_key_hex"])
                    assert len(key) == 32
                    mask = hmac.digest(key, mask_input, "sha256")[:half]
                    assert r["mask_hex"] == mask.hex()
                    current = right + xor(left, mask) if direction == "encryption" else xor(right, mask) + left
                    assert r["left_after_hex"] == current[:half].hex()
                    assert r["right_after_hex"] == current[half:].hex()
                    round_count += 1
                assert current == finish
            if suite == 3:
                detected = matches(state)
                lengths = detected if len(detected) == 1 else detected + [24]
                if not detected:
                    lengths = [24]
                recovery = [{"words": n, "verified": n < 24,
                             "phrase": encode(state[:n // 3 * 4])} for n in lengths]
                assert vector["recovery"] == recovery
            else:
                assert vector["recovery"] == {"words": len(inputs["phrase"].split()),
                                              "verified": False, "phrase": encode(entropy)}
            vectors.append(path.name)

    # Independent byte and arithmetic checks of the optional profiles.
    wallet_results = []
    for counter, passphrase, expected in [
        (76562, "TREZOR", "0000e86481bdfe6dbf45e6e41fba4f309fcf09d3f0af2fe3f46736c663840853"),
        (98918, "", "0000ede77b44fbd62025e1d36a45ebe3846cf48f7b3e76ca6a91495fdadc1fb2"),
    ]:
        entropy = bytes(24) + counter.to_bytes(8, "big")
        mnemonic = encode(entropy)
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic" + passphrase.encode(), 2048)
        tagged = hashlib.sha256(b"MHFE-WALLET-CHECK-SEED-1" + struct.pack(">I", 256) + seed).hexdigest()
        assert tagged == expected
        wallet_results.append({"counter": counter, "passphrase": passphrase, "digest": tagged})

    # Multiplication by polynomial reduction, independent of the implementation's log tables.
    def mul(a, b):
        value = 0
        while b:
            if b & 1:
                value ^= a
            b >>= 1
            a <<= 1
            if a & 2048:
                a ^= 0x805  # x^11 + x^2 + 1 from MHFE-REPAIR-1.
        return value

    value, powers = 1, set()
    for _ in range(2047):
        assert value not in powers and value != 0
        powers.add(value)
        value = mul(value, 2)
    assert value == 1 and len(powers) == 2047
    generators = {}
    for k, expected in [(2, [1, 6, 8]), (4, [1, 30, 216, 960, 1024]),
                        (6, [1, 126, 1181, 1719, 2029, 1077, 1034]),
                        (8, [1, 510, 1509, 1770, 1837, 850, 1339, 600, 680])]:
        g, alpha = [1], 1
        for power in range(1, k + 1):
            alpha = mul(alpha, 2)
            result = [0] * (len(g) + 1)
            for i, coefficient in enumerate(g):
                result[i] ^= coefficient
                result[i + 1] ^= mul(coefficient, alpha)
            g = result
        assert g == expected
        generators[k] = g

    def parity(data, k):
        # Literal polynomial long division instead of the streaming recurrence in repair.rs.
        buffer = list(data) + [0] * k
        for i in range(len(data)):
            lead = buffer[i]
            for j, coefficient in enumerate(generators[k]):
                buffer[i + j] ^= mul(lead, coefficient)
        return buffer[-k:]

    repair_expected = {
        "zero-12.json": ["labor extra", "shaft pupil patient jewel", "credit buzz orbit tired sail coffee", "appear include vicious move uphold tiger song satoshi"],
        "same-length-nonzero-12.json": ["motor renew", "pitch lonely onion erode", "toe rather ribbon run enforce notice", "tilt object execute change cube domain vehicle hour"],
        "same-length-nonzero-21.json": ["glove blossom", "share mask pave crystal", "slow issue fame census cabbage clarify", "potato enemy similar myself check gesture fortune shiver"],
        "zero-24-source": ["clever gravity", "letter wealth borrow cable", "clap try lift setup innocent gather", "mirror coffee census note proof zebra begin barrel"],
    }
    repair_checked = 0
    for name, expected in repair_expected.items():
        if name == "zero-24-source":
            container = encode(bytes(32))
        else:
            suite = 4 if name.startswith("same-length") else 3
            container = json.loads((root / "tests" / "fixtures" / f"suite{suite}-vectors" / name).read_text())["container"]
        data = [indexes[word] for word in container.split()]
        for k, text in zip([2, 4, 6, 8], expected):
            assert " ".join(words[i] for i in parity(data, k)) == text
            repair_checked += 1

    eff_path = root / "vendor" / "eff-large-wordlist" / "eff_large_wordlist.txt"
    assert digest(eff_path) == "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
    eff = [line.split("\t")[1] for line in eff_path.read_text().splitlines()]
    assert len(eff) == 7776 and len(set(eff)) == 7776
    weights = [1, 5, 7, 11, 13]
    import math
    assert all(math.gcd(w, 7776) == 1 for w in weights)
    password_rows = [
        (["11111", "11112", "11113", "11114", "11115"], 104, "abacus abdomen abdominal abide abiding aids"),
        (["66666"] * 5, 7739, "zoom zoom zoom zoom zoom yelling"),
        (["35214", "62431", "15543", "44126", "21365"], 4150, "jovial trailing chokehold pavilion cresting ninth"),
        (["24255", "61534", "11111", "66622", "26522"], 5527, "drop-down t-shirt abacus yo-yo felt-tip rubble"),
    ]
    for rolls, expected_index, expected_password in password_rows:
        drawn = []
        for roll in rolls:
            index = 0
            for digit in roll:
                index = 6 * index + int(digit) - 1
            drawn.append(index)
        check = sum(w * i for w, i in zip(weights, drawn)) % 7776
        assert check == expected_index
        assert " ".join(eff[i] for i in drawn + [check]) == expected_password
        for missing in range(5):
            other = sum(w * i for j, (w, i) in enumerate(zip(weights, drawn)) if j != missing)
            restored = ((check - other) * pow(weights[missing], -1, 7776)) % 7776
            assert restored == drawn[missing]

    source_paths = ["src/suite.rs", "src/feistel.rs", "src/packing.rs", "src/password.rs",
                    "src/phrase.rs", "src/mhfe.rs", "src/rehearsal.rs", "src/wallet_check.rs",
                    "src/repair.rs", "src/wallet.rs", "src/bin/mhfe/check_word.rs"]
    summary = {"outcome": "passed", "positive_vector_count": len(vectors),
               "round_arithmetic_count": round_count, "argon2_calls": 0,
               "wallet_source_vectors": wallet_results, "repair_vector_count": repair_checked,
               "password_check_vector_count": len(password_rows),
               "wordlist_source": str(args.wordlist), "wordlist_sha256": digest(args.wordlist),
               "python_unicode_version": unicodedata.unidata_version,
               "source_sha256": {p: digest(root / p) for p in source_paths},
               "spec_sha256": {p: digest(spec / p) for p in ["README.md", "docs/DESIGN-NOTES.md"]},
               "fixture_sha256": fixture_hashes,
               "limitations": ["Recorded Argon2 outputs are inputs to this probe, not independently verified outputs.",
                               "No full-cost or reduced-cost Argon2 executed.",
                               "Unicode normalization only checked for retained vector characters, not all Unicode 17.",
                               "Repair correction paths require separate production probes; this checks parity and field algebra.",
                               "No theorem or attack-cost lower bound is established."]}
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        raise
