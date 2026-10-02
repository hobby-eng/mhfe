"""Independent implementation of MHFE suite 4, the same-length containers, for checking the Rust
implementation.

Written from the specification alone, like scripts/independent-suite3.py, whose word list, BIP39
coding, password rule and OpenSSL Argon2id it uses unchanged. Install the packages with
`python3 -m pip install --require-hashes -r scripts/independent-suite3-requirements.txt`.
Only public test inputs belong here.

Usage:
    python3 scripts/independent-suite4.py encrypt "<phrase>" "<password>" [PIM] [MEM]
    python3 scripts/independent-suite4.py vector [--trust-argon2-keys] [--record <file>] <file.json> ...
    python3 scripts/independent-suite4.py validation tests/fixtures/suite4-vectors/validation-cases.json

`vector` checks suite 4 vector files and their negative-cases.json: it recomputes every value in
both directions, including every Argon2id call. With --trust-argon2-keys it takes the recorded
Argon2id outputs as given, looked up by their salt, and checks everything else. --record adds the
checked files to a JSON record, normally tests/fixtures/suite4-vectors/independent-verification.json,
in the layout of the suite 3 record.

`validation` checks the fast cases, which need no Argon2id: that `ENT` is part of every round
message, and the inputs that must be refused before any Argon2id work.
"""

import hashlib
import hmac
import importlib.util
import json
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("suite3", os.path.join(_here, "independent-suite3.py"))
suite3 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(suite3)

SUITE_ID = b"MHFE-BIP39-LP-EXPERIMENTAL-4"
DS_SALT = SUITE_ID + b"/ROUND-SALT"
DS_MASK = SUITE_ID + b"/ROUND-MASK"
SCHEMA = "mhfe-suite-4-vector-v1"
NEGATIVE_SCHEMA = "mhfe-suite-4-negative-case-v1"
VALIDATION_SCHEMA = "mhfe-suite-4-validation-cases-v1"
ROUNDS = suite3.ROUNDS
# Entropy bytes of the lengths suite 4 takes; a 24-word source has no suite 4 form.
SHORT_LENGTHS = suite3.SHORT_LENGTHS


def round_message(pim, level, entropy_bits, round_index, half):
    """BE32(MEM) || BE32(PIM) || BE32(ENT) || BE32(i) || R."""
    be32 = suite3.be32
    return be32(level) + be32(pim) + be32(entropy_bits) + be32(round_index) + half


def round_values(argon2, password, pim, level, entropy_bits, round_index, right):
    """The salt input, salt, Argon2id output, mask input and mask of one round."""
    message = round_message(pim, level, entropy_bits, round_index, right)
    salt_input, mask_input = DS_SALT + message, DS_MASK + message
    salt = hashlib.blake2b(salt_input, digest_size=32).digest()[:16]
    key = argon2(password, salt, pim, level)
    mask = hmac.new(key, mask_input, hashlib.sha256).digest()[: len(right)]
    return salt_input, salt, key, mask_input, mask


def forward(x, argon2, password, pim, level):
    half, entropy_bits = len(x) // 2, 8 * len(x)
    left, right = x[:half], x[half:]
    rounds = []
    for index in range(ROUNDS):
        values = round_values(argon2, password, pim, level, entropy_bits, index, right)
        before = left + right
        left, right = right, suite3.xor(left, values[-1])
        rounds.append((index, before, *values, left + right))
    return left + right, rounds


def inverse(y, argon2, password, pim, level):
    half, entropy_bits = len(y) // 2, 8 * len(y)
    left, right = y[:half], y[half:]
    rounds = []
    for index in reversed(range(ROUNDS)):
        values = round_values(argon2, password, pim, level, entropy_bits, index, left)
        before = left + right
        left, right = suite3.xor(right, values[-1]), left
        rounds.append((index, before, *values, left + right))
    return left + right, rounds


def short_entropy(phrase):
    entropy = suite3.phrase_to_entropy(phrase)
    assert len(entropy) in SHORT_LENGTHS.values(), "suite 4 takes 12, 15, 18 or 21 words"
    return entropy


def encrypt(phrase, password_text, pim=0, level=0):
    password = suite3.encode_password(password_text.encode("utf-8"))
    y, _ = forward(short_entropy(phrase), suite3.openssl_argon2id, password, pim, level)
    return suite3.entropy_to_phrase(y)


def check_header(record, schema):
    assert record["schema"] == schema, record["schema"]
    assert record["suite_id"] == SUITE_ID.decode()
    generator = record["generator"]
    assert generator["program"] == "mhfe test-vectors"
    assert generator["version"] and generator["argon2"], "the generator is not named"


def check_vector(vector, trust_keys):
    check_header(vector, SCHEMA)
    inputs = vector["inputs"]
    pim, level = inputs["pim"], inputs["memory_level"]
    assert inputs["password"].encode().hex() == inputs["password_utf8_hex"]
    password = suite3.check_password(
        {"password": inputs["password"], "password_nfkd_utf8_hex": inputs["password_nfkd_utf8_hex"]}
    )
    assert vector["argon2"] == {
        "variant": "Argon2id",
        "version": suite3.ARGON2_VERSION,
        "memory_kib": suite3.memory_kib(level),
        "passes": suite3.passes(pim),
        "lanes": suite3.LANES,
        "output_bytes": suite3.KEY_BYTES,
    }, vector["argon2"]
    argon2 = suite3.recorded_keys_by_salt(vector) if trust_keys else suite3.openssl_argon2id

    # X = E: no packing and no verifier.
    x = short_entropy(inputs["phrase"])
    words = len(inputs["phrase"].split())
    assert vector["state"] == {
        "words": words,
        "entropy_bits": 8 * len(x),
        "half_bytes": len(x) // 2,
        "state_hex": x.hex(),
    }, vector["state"]

    assert vector["encryption"]["input_state_hex"] == x.hex()
    y, forward_rounds = forward(x, argon2, password, pim, level)
    suite3.check_rounds(vector["encryption"]["rounds"], forward_rounds, "encryption")
    assert y.hex() == vector["encryption"]["output_state_hex"]
    assert y != x, "a fixed point is refused"
    container = suite3.entropy_to_phrase(y)
    assert container == vector["container"] and len(container.split()) == words

    container_state = short_entropy(vector["container"])
    assert vector["decryption"]["input_state_hex"] == container_state.hex()
    recovered, inverse_rounds = inverse(container_state, argon2, password, pim, level)
    suite3.check_rounds(vector["decryption"]["rounds"], inverse_rounds, "decryption")
    assert recovered == x
    assert vector["decryption"]["output_state_hex"] == x.hex()
    assert vector["recovery"] == {
        "words": words,
        "verified": False,
        "phrase": suite3.entropy_to_phrase(recovered),
    }, "recovery"


def check_negative_case(case):
    """Recovery with a wrong password or setting gives another phrase of the same length and no
    error; another chosen length is refused before any Argon2id work."""
    check_header(case, NEGATIVE_SCHEMA)
    pim, level, words = case["pim"], case["memory_level"], case["words"]
    password = suite3.check_password(case)
    container_words = len(case["container"].split())
    if words not in (0, container_words):
        expected, error = [], "LENGTH_CHOICE_NOT_APPLICABLE"
    else:
        y = short_entropy(case["container"])
        x, _ = inverse(y, suite3.openssl_argon2id, password, pim, level)
        expected, error = [(container_words, False, suite3.entropy_to_phrase(x))], None
    recorded = [(c["words"], c["verified"], c["phrase"]) for c in case["recovery"]]
    assert (recorded, case["error_code"]) == (expected, error), case["name"]


def check_validation_cases(path):
    """The fast cases: ENT in every round message, and the inputs refused before Argon2id."""
    fixture = json.load(open(path, encoding="utf-8"))
    assert fixture["schema"] == VALIDATION_SCHEMA and fixture["suite_id"] == SUITE_ID.decode()
    for case in fixture["ent_separation"]:
        half = bytes.fromhex(case["half_hex"])
        assert len(half) * 16 == case["entropy_bits"], case["id"]
        message = round_message(case["pim"], case["memory_level"], case["entropy_bits"], case["round"], half)
        assert (DS_SALT + message).hex() == case["salt_input_hex"], case["id"]
        assert hashlib.blake2b(DS_SALT + message, digest_size=32).digest()[:16].hex() == case["salt_hex"], case["id"]
        key = bytes.fromhex(case["key_hex"])
        assert (DS_MASK + message).hex() == case["mask_input_hex"], case["id"]
        mask = hmac.new(key, DS_MASK + message, hashlib.sha256).digest()[: len(half)]
        assert mask.hex() == case["mask_hex"], case["id"]
    salts = [case["salt_hex"] for case in fixture["ent_separation"]]
    assert len(set(salts)) == len(salts), "ENT must separate the salts"
    # The recovery table: a chosen original length, a selected suite or both admit only these
    # container word counts; every refusal case must fall outside them.
    def admitted(length, suite, words):
        by_length = length is None or words == 24 or (length < 24 and words == length)
        by_suite = suite is None or (words == 24) == (suite == 3)
        return by_length and by_suite

    for case in fixture["refusals"]:
        assert case["expected"] == "rejected", case["id"]
        words = len(case["text"].split())
        if case["operation"] == "encrypt-same-length":
            assert words == 24, case["id"]
        else:
            assert case["operation"] == "decrypt", case["id"]
            assert not admitted(case.get("words"), case.get("suite"), words), case["id"]
    print(
        f"{path}: {len(fixture['ent_separation'])} ENT cases reproduced, "
        f"{len(fixture['refusals'])} refusals consistent"
    )


def check_files(paths, trust_keys):
    checked = []
    for path in paths:
        content = json.load(open(path, encoding="utf-8"))
        if isinstance(content, list):
            if trust_keys:
                print(f"{path}: skipped, negative cases need the full Argon2id check")
                continue
            for case in content:
                check_negative_case(case)
            print(f"{path}: all {len(content)} negative cases reproduced", flush=True)
        else:
            check_vector(content, trust_keys)
            how = "with the recorded Argon2id keys" if trust_keys else "in both directions"
            print(f"{path}: every value reproduced {how}", flush=True)
        checked.append((path, "recorded-argon2-keys" if trust_keys else "full"))
    return checked


# Taken before main() puts verifier_description below in its place, which would otherwise call
# itself.
suite3_verifier_description = suite3.verifier_description


def verifier_description():
    description = suite3_verifier_description()
    description["program"] = "scripts/independent-suite4.py"
    description["sha256"] = suite3.sha256_file(__file__)
    description["suite3_helpers_sha256"] = suite3.sha256_file(_spec.origin)
    return description


def main(arguments):
    command, arguments = arguments[0], arguments[1:]
    if command == "encrypt":
        extra = [int(value) for value in arguments[2:4]]
        print(encrypt(arguments[0], arguments[1], *extra))
        return
    if command == "validation":
        for path in arguments:
            check_validation_cases(path)
        return
    if command != "vector":
        sys.exit(__doc__)
    trust = "--trust-argon2-keys" in arguments
    arguments = [value for value in arguments if value != "--trust-argon2-keys"]
    record_path = None
    if "--record" in arguments:
        position = arguments.index("--record")
        record_path = arguments[position + 1]
        del arguments[position : position + 2]
    checked = check_files(arguments, trust)
    if record_path is not None:
        # The suite 3 record format, with this script as the verifier.
        suite3.verifier_description = verifier_description
        suite3.update_record(record_path, checked)


if __name__ == "__main__":
    main(sys.argv[1:])
