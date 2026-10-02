"""Independent implementation of MHFE suite 3 for checking the Rust implementation.

Written from the specification alone. It shares no code with the Rust crate: Argon2id comes from
OpenSSL through Python `cryptography`, BLAKE2b, HMAC and SHA-256 from Python's standard library,
and the Unicode 17.0.0 character database of the password rule from `unicodedata2`, because
Python's own `unicodedata` is an older Unicode version. Install the packages with
`python3 -m pip install --require-hashes -r scripts/independent-suite3-requirements.txt`.
Only public test inputs belong here.

Usage:
    python3 scripts/independent-suite3.py encrypt "<phrase>" "<password>" [PIM] [MEM]
    python3 scripts/independent-suite3.py vector [--trust-argon2-keys] [--record <file>] <file.json> ...
    python3 scripts/independent-suite3.py passwords tests/fixtures/validation-cases.json

`vector` checks vector files and negative-cases.json: it recomputes every value in both
directions, including every Argon2id call, about ten seconds each at the defaults. With
--trust-argon2-keys it takes the recorded Argon2id outputs as given, looked up by their salt, and
checks everything else within a second: packing, salts, masks, rounds, container and recovery.
Negative cases have no recorded keys and need the full check.

`passwords` checks every password-encoding case of the validation fixture: the NFKD result or the
error that the password rule of the specification gives, including the Unicode 17 rule for
unassigned code points.

--record adds the checked files to a JSON record, normally
tests/fixtures/suite3-vectors/independent-verification.json: the SHA-256 of this script, the
Python, `cryptography`, `unicodedata2` and OpenSSL versions, and for each file its SHA-256 and how it was checked
("full" or "recorded-argon2-keys"). Runs with the same script add to the record; a file whose
bytes changed, or a changed script, starts its entry again.

The BIP39 English wordlist is read from the `bip39` crate sources in the Cargo registry, or from
the file named by the environment variable BIP39_ENGLISH_WORDLIST (one word per line).
"""

import glob
import hashlib
import hmac
import importlib.metadata
import json
import os
import platform
import re
import sys

try:
    import unicodedata2 as unicode17
except ImportError:
    sys.exit("Needs unicodedata2: python3 -m pip install --require-hashes -r scripts/independent-suite3-requirements.txt")

# The password rule uses this exact Unicode version (the specification, "Password encoding").
UNICODE_VERSION = "17.0.0"
if unicode17.unidata_version != UNICODE_VERSION:
    sys.exit(f"unicodedata2 has Unicode {unicode17.unidata_version}, the password rule needs {UNICODE_VERSION}")
# Longest password after NFKD, in bytes.
MAX_PASSWORD_BYTES = 1024

SUITE_ID = b"MHFE-BIP39-256-EXPERIMENTAL-3"
DS_SALT = SUITE_ID + b"/ROUND-SALT"
DS_MASK = SUITE_ID + b"/ROUND-MASK"
SCHEMA = "mhfe-suite-3-vector-v2"
NEGATIVE_SCHEMA = "mhfe-suite-3-negative-case-v2"
ROUNDS = 12
LANES = 4
# Argon2 version 1.3, as the specification and RFC 9106 write it.
ARGON2_VERSION = 0x13
KEY_BYTES = 32
# Entropy bytes of the short phrase lengths, in the order detection tests them.
SHORT_LENGTHS = {12: 16, 15: 20, 18: 24, 21: 28}


def english_wordlist():
    path = os.environ.get("BIP39_ENGLISH_WORDLIST")
    if path:
        words = open(path, encoding="ascii").read().split()
    else:
        cargo_home = os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))
        pattern = os.path.join(cargo_home, "registry/src/*/bip39-3.0.0/src/language/english.rs")
        source = open(sorted(glob.glob(pattern))[0], encoding="utf-8").read()
        words = re.findall(r'"([a-z]+)"', source)
    assert len(words) == 2048, "the English wordlist must have 2048 words"
    return words


WORDS = english_wordlist()


def phrase_to_entropy(phrase):
    indexes = [WORDS.index(word) for word in phrase.split()]
    bits = "".join(format(index, "011b") for index in indexes)
    checksum_bits = len(bits) // 33
    entropy = int(bits[:-checksum_bits], 2).to_bytes((len(bits) - checksum_bits) // 8, "big")
    expected = format(hashlib.sha256(entropy).digest()[0], "08b")[:checksum_bits]
    assert bits[-checksum_bits:] == expected, "invalid BIP39 checksum"
    return entropy


def entropy_to_phrase(entropy):
    checksum_bits = len(entropy) * 8 // 32
    bits = format(int.from_bytes(entropy, "big"), f"0{len(entropy) * 8}b")
    bits += format(hashlib.sha256(entropy).digest()[0], "08b")[:checksum_bits]
    return " ".join(WORDS[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


def memory_kib(level):
    return (2 + level % 2) << (20 + level // 2)


def passes(pim):
    return 12 * (pim + 1)


def be32(value):
    return value.to_bytes(4, "big")


def openssl_argon2id(password, salt, pim, level):
    """K_i: Argon2id version 1.3, four lanes, 32 bytes, empty secret and associated data."""
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    kdf = Argon2id(
        salt=salt, length=32, iterations=passes(pim), lanes=LANES, memory_cost=memory_kib(level)
    )
    return kdf.derive(password)


def round_values(argon2, password, pim, level, round_index, right):
    """The salt input, salt, Argon2id output, mask input and mask of one round."""
    message = be32(level) + be32(pim) + be32(round_index) + right
    salt_input, mask_input = DS_SALT + message, DS_MASK + message
    salt = hashlib.blake2b(salt_input, digest_size=32).digest()[:16]
    key = argon2(password, salt, pim, level)
    mask = hmac.new(key, mask_input, hashlib.sha256).digest()[:16]
    return salt_input, salt, key, mask_input, mask


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def forward(x, argon2, password, pim, level):
    left, right = x[:16], x[16:]
    rounds = []
    for index in range(ROUNDS):
        values = round_values(argon2, password, pim, level, index, right)
        before = left + right
        left, right = right, xor(left, values[-1])
        rounds.append((index, before, *values, left + right))
    return left + right, rounds


def inverse(y, argon2, password, pim, level):
    left, right = y[:16], y[16:]
    rounds = []
    for index in reversed(range(ROUNDS)):
        values = round_values(argon2, password, pim, level, index, left)
        before = left + right
        left, right = xor(right, values[-1]), left
        rounds.append((index, before, *values, left + right))
    return left + right, rounds


def pack(entropy):
    return entropy + hashlib.sha256(entropy).digest()[: 32 - len(entropy)]


def matching_short_lengths(x):
    return [
        words
        for words, length in SHORT_LENGTHS.items()
        if hashlib.sha256(x[:length]).digest()[: 32 - length] == x[length:]
    ]


def detected_recovery(x):
    """Step 3 of recovery with detection: one match, the 24-word reading, or all of them."""
    lengths = matching_short_lengths(x)
    if len(lengths) == 1:
        return [(lengths[0], True, read_as(x, lengths[0]))]
    candidates = [(words, True, read_as(x, words)) for words in lengths]
    return candidates + [(24, False, read_as(x, 24))]


def read_as(x, words):
    return entropy_to_phrase(x[: SHORT_LENGTHS.get(words, 32)])


class PasswordRefused(Exception):
    """A password the rule refuses; `code` is the error the specification names."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def encode_password(raw):
    """P_enc = UTF8(NFKD(P)) under the password rule of the specification, from UTF-8 bytes."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise PasswordRefused("INVALID_PASSWORD_UTF8") from None
    if any(map(is_refused_in_password, text)):
        raise PasswordRefused("CONTROL_CHARACTER_IN_PASSWORD")
    # Stabilized normalization fails on a code point that Unicode 17.0.0 leaves unassigned (Cn),
    # the noncharacters included; Private Use (Co) is assigned.
    if any(unicode17.category(character) == "Cn" for character in text):
        raise PasswordRefused("UNASSIGNED_CHARACTER")
    encoded = unicode17.normalize("NFKD", text).encode("utf-8")
    if not encoded:
        raise PasswordRefused("EMPTY_PASSWORD")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordRefused("PASSWORD_TOO_LONG")
    return encoded


def check_password_cases(path):
    """Every password case of the validation fixture: its NFKD bytes, or their count, or its error.

    A case gives its input either as UTF-8 hex or as a piece repeated `count` times; a long result
    is given by its length in bytes.
    """
    cases = json.load(open(path, encoding="utf-8"))["passwords"]
    for case in cases:
        if "input_utf8_hex" in case:
            raw = bytes.fromhex(case["input_utf8_hex"])
        else:
            raw = bytes.fromhex(case["repeat_utf8_hex"]) * case["count"]
        try:
            encoded = encode_password(raw)
        except PasswordRefused as refusal:
            assert refusal.code == case.get("expected_error"), (
                f"password case {case['id']}: refused with {refusal.code}, expected {case.get('expected_error')}"
            )
            if "expected_nfkd_bytes" in case:
                length = len(unicode17.normalize("NFKD", raw.decode("utf-8")).encode("utf-8"))
                assert length == case["expected_nfkd_bytes"], f"password case {case['id']}: {length} bytes"
            continue
        assert "expected_error" not in case, f"password case {case['id']}: accepted, expected {case['expected_error']}"
        if "expected_nfkd_utf8_hex" in case:
            assert encoded.hex() == case["expected_nfkd_utf8_hex"], f"password case {case['id']}: {encoded.hex()}"
        else:
            assert len(encoded) == case["expected_nfkd_bytes"], f"password case {case['id']}: {len(encoded)} bytes"
    print(f"{path}: all {len(cases)} password cases reproduced with Unicode {UNICODE_VERSION}")


def encrypt(phrase, password_text, pim=0, level=0):
    password = encode_password(password_text.encode("utf-8"))
    y, _ = forward(pack(phrase_to_entropy(phrase)), openssl_argon2id, password, pim, level)
    return entropy_to_phrase(y)


def recorded_keys_by_salt(vector):
    """The --trust-argon2-keys source of K_i: the recorded output for each recorded salt."""
    keys = {}
    for direction in ("encryption", "decryption"):
        for entry in vector[direction]["rounds"]:
            keys[entry["salt_hex"]] = bytes.fromhex(entry["argon2_key_hex"])

    def argon2(password, salt, pim, level):
        assert salt.hex() in keys, f"salt {salt.hex()} was not recorded"
        return keys[salt.hex()]

    return argon2


def is_refused_in_password(character):
    """Control characters (General_Category Cc) and the line and paragraph separators."""
    return unicode17.category(character) == "Cc" or character in "\u2028\u2029"


def check_password(record):
    password = bytes.fromhex(record["password_nfkd_utf8_hex"])
    assert encode_password(record["password"].encode("utf-8")) == password, (
        "the password rule does not give password_nfkd_utf8_hex"
    )
    return password


def check_header(record, schema):
    """The layout name, the suite and what wrote the file."""
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
    password = check_password(
        {"password": inputs["password"], "password_nfkd_utf8_hex": inputs["password_nfkd_utf8_hex"]}
    )
    assert vector["argon2"] == {
        "variant": "Argon2id",
        "version": ARGON2_VERSION,
        "memory_kib": memory_kib(level),
        "passes": passes(pim),
        "lanes": LANES,
        "output_bytes": KEY_BYTES,
    }, vector["argon2"]
    argon2 = recorded_keys_by_salt(vector) if trust_keys else openssl_argon2id

    entropy = phrase_to_entropy(inputs["phrase"])
    x = pack(entropy)
    assert vector["packing"] == {
        "words": len(inputs["phrase"].split()),
        "entropy_hex": entropy.hex(),
        "verifier_hex": x[len(entropy):].hex(),
        "state_hex": x.hex(),
    }, vector["packing"]

    assert vector["encryption"]["input_state_hex"] == x.hex()
    y, forward_rounds = forward(x, argon2, password, pim, level)
    check_rounds(vector["encryption"]["rounds"], forward_rounds, "encryption")
    assert y.hex() == vector["encryption"]["output_state_hex"]
    assert entropy_to_phrase(y) == vector["container"]

    container_state = phrase_to_entropy(vector["container"])
    assert vector["decryption"]["input_state_hex"] == container_state.hex()
    recovered, inverse_rounds = inverse(container_state, argon2, password, pim, level)
    check_rounds(vector["decryption"]["rounds"], inverse_rounds, "decryption")
    assert recovered == x
    assert vector["decryption"]["output_state_hex"] == x.hex()
    recorded = [(c["words"], c["verified"], c["phrase"]) for c in vector["recovery"]]
    assert recorded == detected_recovery(recovered), "recovery"


def check_negative_case(case):
    """Recovery with a wrong password or setting: the recorded phrases or error."""
    check_header(case, NEGATIVE_SCHEMA)
    pim, level, words = case["pim"], case["memory_level"], case["words"]
    password = check_password(case)
    x, _ = inverse(phrase_to_entropy(case["container"]), openssl_argon2id, password, pim, level)
    if words == 0:
        expected, error = detected_recovery(x), None
    elif words == 24:
        expected, error = [(24, False, read_as(x, 24))], None
    elif words in matching_short_lengths(x):
        expected, error = [(words, True, read_as(x, words))], None
    else:
        expected, error = [], "VERIFIER_MISMATCH"
    recorded = [(c["words"], c["verified"], c["phrase"]) for c in case["recovery"]]
    assert (recorded, case["error_code"]) == (expected, error), case["name"]
    assert read_as(x, 24) != "", case["name"]


def check_rounds(recorded, computed, label):
    assert len(recorded) == len(computed) == ROUNDS, label
    for entry, (index, before, salt_input, salt, key, mask_input, mask, after) in zip(
        recorded, computed
    ):
        assert entry["round"] == index, label
        assert entry["left_before_hex"] + entry["right_before_hex"] == before.hex(), (label, index)
        assert entry["salt_input_hex"] == salt_input.hex(), (label, index, "salt input")
        assert entry["salt_hex"] == salt.hex(), (label, index, "salt")
        assert entry["argon2_key_hex"] == key.hex(), (label, index, "key")
        assert entry["mask_input_hex"] == mask_input.hex(), (label, index, "mask input")
        assert entry["mask_hex"] == mask.hex(), (label, index, "mask")
        assert entry["left_after_hex"] + entry["right_after_hex"] == after.hex(), (label, index)


def sha256_file(path):
    with open(path, "rb") as file:
        return hashlib.sha256(file.read()).hexdigest()


def check_files(paths, trust_keys):
    """Checks each file and returns the (path, mode) of every file that was checked."""
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


def verifier_description():
    """What ran the check, so that a reader can tell which implementation agreed."""
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend

    return {
        "program": "scripts/independent-suite3.py",
        "sha256": sha256_file(__file__),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        # The compiled module carries no __version__; the installed package names its version.
        "unicodedata2": (
            f"{importlib.metadata.version('unicodedata2')} (Unicode {unicode17.unidata_version})"
        ),
        "openssl": backend.openssl_version_text(),
    }


def update_record(record_path, checked):
    """Adds the checked files to the record, keeping entries that are still valid.

    Several checks may run side by side and add to one record, so the file is locked while it is
    read and rewritten (fcntl: this development script runs on Linux and macOS).
    """
    import fcntl

    verifier = verifier_description()
    with open(record_path, "a+", encoding="utf-8") as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        file.seek(0)
        text = file.read()
        record = json.loads(text) if text else None
        if record is None or record.get("verifier") != verifier:
            record = {"schema": "mhfe-independent-verification-v1", "verifier": verifier, "files": []}

        entries = {entry["name"]: entry for entry in record["files"]}
        for path, mode in checked:
            name, digest = os.path.basename(path), sha256_file(path)
            entry = entries.get(name)
            if entry is None or entry["sha256"] != digest:
                entry = entries[name] = {"name": name, "sha256": digest, "checks": []}
            if mode not in entry["checks"]:
                entry["checks"] = sorted(entry["checks"] + [mode])
        record["files"] = [entries[name] for name in sorted(entries)]

        file.seek(0)
        file.truncate()
        json.dump(record, file, indent=2)
        file.write("\n")
    print(f"{record_path}: recorded {len(checked)} checked files")


def main(arguments):
    command, arguments = arguments[0], arguments[1:]
    if command == "encrypt":
        extra = [int(value) for value in arguments[2:4]]
        print(encrypt(arguments[0], arguments[1], *extra))
        return
    if command == "passwords":
        for path in arguments:
            check_password_cases(path)
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
        update_record(record_path, checked)


if __name__ == "__main__":
    main(sys.argv[1:])
