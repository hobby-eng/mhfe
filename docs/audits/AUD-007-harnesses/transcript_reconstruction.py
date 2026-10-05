"""Reconstruct public suite 3/4 transcripts without recomputing their Argon2 outputs."""

import hashlib
import hmac
import json
from pathlib import Path
import struct
import unicodedata


ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests/fixtures"
SUITES = (
    ("suite3-vectors", "MHFE-BIP39-256-EXPERIMENTAL-3", 17),
    ("suite4-vectors", "MHFE-BIP39-LP-EXPERIMENTAL-4", 10),
)
# Frozen suite parameters; sizes below are bytes unless their names say otherwise.
ROUNDS = 12
STATE_BYTES = 32
SALT_BYTES = 16
KEY_BYTES = 32
LANES = 4
ARGON2_VERSION = 0x13
BASE_PASSES = 12
MAX_PIM = 1023
MAX_MEMORY_LEVEL = 21


def require(condition, context):
    if not condition:
        raise AssertionError(context)


def unhex(text):
    return bytes.fromhex(text)


def check_parameters(vector, path):
    inputs = vector["inputs"]
    pim = inputs["pim"]
    memory_level = inputs["memory_level"]
    require(0 <= pim <= MAX_PIM, f"{path}: PIM range")
    require(0 <= memory_level <= MAX_MEMORY_LEVEL, f"{path}: memory-level range")
    expected_memory = (2 + memory_level % 2) * 2 ** (20 + memory_level // 2)
    expected_argon2 = {
        "variant": "Argon2id",
        "version": ARGON2_VERSION,
        "memory_kib": expected_memory,
        "passes": BASE_PASSES * (pim + 1),
        "lanes": LANES,
        "output_bytes": KEY_BYTES,
    }
    require(vector["argon2"] == expected_argon2, f"{path}: Argon2 parameters")
    # These existing public fixture spellings normalize identically in Python's database.
    # This is not a test of MHFE's pinned Unicode 17 character-acceptance rules.
    normalized = unicodedata.normalize("NFKD", inputs["password"]).encode("utf-8")
    require(
        normalized.hex() == inputs["password_nfkd_utf8_hex"],
        f"{path}: recorded normalized password bytes",
    )
    return struct.pack(">II", memory_level, pim)


def check_geometry(vector, suite4, path):
    if suite4:
        geometry = vector["state"]
        entropy_bits = geometry["entropy_bits"]
        half_bytes = geometry["half_bytes"]
        require(entropy_bits in (128, 160, 192, 224), f"{path}: suite 4 entropy width")
        require(half_bytes * 16 == entropy_bits, f"{path}: suite 4 half width")
        require(
            len(unhex(geometry["state_hex"])) == half_bytes * 2,
            f"{path}: suite 4 state width",
        )
        return half_bytes, struct.pack(">I", entropy_bits)

    packing = vector["packing"]
    entropy = unhex(packing["entropy_hex"])
    require(len(entropy) in (16, 20, 24, 28, 32), f"{path}: suite 3 entropy width")
    verifier = hashlib.sha256(entropy).digest()[: STATE_BYTES - len(entropy)]
    require(packing["verifier_hex"] == verifier.hex(), f"{path}: packed verifier")
    require(
        packing["state_hex"] == (entropy + verifier).hex(),
        f"{path}: packed state",
    )
    return STATE_BYTES // 2, b""


def reconstruct_phase(vector, direction, suite_id, header, half_bytes, path):
    phase = vector[direction]
    state = unhex(phase["input_state_hex"])
    expected_indexes = list(range(ROUNDS))
    if direction == "decryption":
        expected_indexes.reverse()
    require(
        [record["round"] for record in phase["rounds"]] == expected_indexes,
        f"{path}: {direction} round indexes",
    )
    require(len(state) == half_bytes * 2, f"{path}: {direction} input width")

    for record in phase["rounds"]:
        context = f"{path}: {direction} round {record['round']}"
        left, right = state[:half_bytes], state[half_bytes:]
        require(left.hex() == record["left_before_hex"], f"{context}: left input")
        require(right.hex() == record["right_before_hex"], f"{context}: right input")
        unchanged = right if direction == "encryption" else left
        message = header + struct.pack(">I", record["round"]) + unchanged
        salt_input = (suite_id + "/ROUND-SALT").encode("ascii") + message
        mask_input = (suite_id + "/ROUND-MASK").encode("ascii") + message
        require(salt_input.hex() == record["salt_input_hex"], f"{context}: salt input")
        require(mask_input.hex() == record["mask_input_hex"], f"{context}: mask input")
        salt = hashlib.blake2b(salt_input, digest_size=KEY_BYTES).digest()[:SALT_BYTES]
        require(salt.hex() == record["salt_hex"], f"{context}: salt")

        # The recorded Argon2 key is an input to this bounded reconstruction, not its result.
        key = unhex(record["argon2_key_hex"])
        require(len(key) == KEY_BYTES, f"{context}: recorded Argon2 key width")
        mask = hmac.new(key, mask_input, hashlib.sha256).digest()[:half_bytes]
        require(mask.hex() == record["mask_hex"], f"{context}: mask")
        if direction == "encryption":
            next_left = right
            next_right = bytes(a ^ b for a, b in zip(left, mask))
        else:
            next_left = bytes(a ^ b for a, b in zip(right, mask))
            next_right = left
        require(next_left.hex() == record["left_after_hex"], f"{context}: left output")
        require(next_right.hex() == record["right_after_hex"], f"{context}: right output")
        state = next_left + next_right

    require(state.hex() == phase["output_state_hex"], f"{path}: {direction} final state")
    return len(phase["rounds"])


def main():
    transcripts = rounds = 0
    inputs = {}
    suite_counts = {}
    for directory, suite_id, expected_count in SUITES:
        suite4 = directory == "suite4-vectors"
        count = 0
        for path in sorted((FIXTURES / directory).glob("*.json")):
            data = path.read_bytes()
            vector = json.loads(data)
            if not isinstance(vector, dict) or "encryption" not in vector:
                continue
            relative_path = str(path.relative_to(ROOT))
            require(vector["suite_id"] == suite_id, f"{relative_path}: suite identifier")
            header = check_parameters(vector, relative_path)
            half_bytes, entropy_width = check_geometry(vector, suite4, relative_path)
            header += entropy_width
            for direction in ("encryption", "decryption"):
                rounds += reconstruct_phase(
                    vector, direction, suite_id, header, half_bytes, relative_path
                )
            encryption = vector["encryption"]
            decryption = vector["decryption"]
            require(
                encryption["input_state_hex"] == decryption["output_state_hex"],
                f"{relative_path}: recovered input state",
            )
            require(
                encryption["output_state_hex"] == decryption["input_state_hex"],
                f"{relative_path}: encrypted output state",
            )
            inputs[relative_path] = hashlib.sha256(data).hexdigest()
            count += 1
        require(count == expected_count, f"{directory}: expected {expected_count} transcripts")
        suite_counts[suite_id] = count
        transcripts += count

    print(json.dumps({
        "positiveTranscripts": transcripts,
        "roundRecordsChecked": rounds,
        "suiteCounts": suite_counts,
        "packingParametersMessagesSaltsMasksStates": "passed",
        "argon2Outputs": "recorded inputs; not recomputed",
        "productionCodeExecuted": False,
        "pythonUnicodeVersion": unicodedata.unidata_version,
        "harnessSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "inputSha256": inputs,
    }, indent=2))


if __name__ == "__main__":
    main()
