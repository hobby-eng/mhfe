#!/usr/bin/env python3
"""AUD-008: independent strict Bech32m padding and BIP32 bounds challenge.

Run from the mhfe checkout with a compiled wallet-challenge-probe path and an
ignored output path. Inputs are synthetic public payloads, without Argon2 or
network calls. Exit 1 means an API contract mismatch was reproduced.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONSTANT = 0x2BC830A3
GENERATORS = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
MAX_CHILD_INDEX = (1 << 31) - 1


def polymod(values):
    checksum = 1
    for value in values:
        high = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate(GENERATORS):
            if (high >> bit) & 1:
                checksum ^= generator
    return checksum


def encode(hrp, words, constant=BECH32M_CONSTANT):
    expanded = [ord(char) >> 5 for char in hrp] + [0]
    expanded += [ord(char) & 31 for char in hrp]
    check = polymod(expanded + words + [0] * 6) ^ constant
    checksum = [(check >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(ALPHABET[word] for word in words + checksum)


def byte_words(payload):
    # A 21-byte payload has 168 bits, so 34 groups leave two zero padding bits.
    bits = "".join(f"{byte:08b}" for byte in payload) + "00"
    return [int(bits[index:index + 5], 2) for index in range(0, len(bits), 5)]


def strict_bytes(words):
    bits = "".join(f"{word:05b}" for word in words)
    residual = len(bits) % 8
    if residual >= 5:
        raise ValueError("excess padding")
    if residual and int(bits[-residual:], 2):
        raise ValueError("nonzero padding")
    return bytes(int(bits[index:index + 8], 2) for index in range(0, len(bits) - residual, 8))


def main():
    probe, output = map(Path, sys.argv[1:])
    payload = bytes([0xB0]) + bytes(range(20))
    words = byte_words(payload)
    assert len(words) == 34 and strict_bytes(words) == payload
    cases = []
    for hrp in ["dash", "tdash"]:
        canonical = encode(hrp, words)
        for name, candidate, accepted in [
            ("canonical", canonical, True),
            ("uppercase", canonical.upper(), True),
            ("mixed-case", canonical[0].upper() + canonical[1:], False),
            ("wrong-checksum-kind", encode(hrp, words, 1), False),
        ]:
            cases.append({"id": f"{hrp}-{name}", "input": ["address", f"{hrp}-{name}", canonical, candidate], "expectedAccepted": accepted})
        mutations = [(f"nonzero-padding-{tail}", words[:-1] + [words[-1] | tail]) for tail in [1, 2, 3]]
        mutations += [(f"extra-group-{tail}", words + [tail]) for tail in [0, 1]]
        for name, malformed in mutations:
            try:
                strict_bytes(malformed)
            except ValueError as error:
                reason = str(error)
            else:
                raise AssertionError("malformed positive control in independent decoder")
            cases.append({"id": f"{hrp}-{name}", "input": ["address", f"{hrp}-{name}", canonical, encode(hrp, malformed)], "expectedAccepted": False, "independentReason": reason})

    paths = [("m", True), (f"m/{MAX_CHILD_INDEX}", True), (f"m/{MAX_CHILD_INDEX}'", True), ("m/0h", True), ("m/-1", False), ("m/+1", False), ("m/1.5", False), ("m/2147483648", False), ("m/4294967296'", False), ("m//0", False), (" m/0", False)]
    for index, (path, accepted) in enumerate(paths):
        cases.append({"id": f"path-{index}", "input": ["path", f"path-{index}", path], "expectedAccepted": accepted})
    limits = [(1, 1, True), (1 << 31, 1 << 31, True), (0, 1, False), (1, 0, False), ((1 << 31) + 1, 1, False)]
    for index, (accounts, indexes, accepted) in enumerate(limits):
        cases.append({"id": f"limit-{index}", "input": ["limit", f"limit-{index}", str(accounts), str(indexes)], "expectedAccepted": accepted})

    completed = subprocess.run([str(probe.resolve())], input="".join("\t".join(case["input"]) + "\n" for case in cases), text=True, capture_output=True, check=True)
    lines = completed.stdout.splitlines()
    assert len(lines) == len(cases)
    for case, line in zip(cases, lines):
        identifier, accepted, same_payload = line.split("\t")
        assert identifier == case["id"]
        case["actualAccepted"] = accepted == "true"
        if case["input"][0] == "address":
            case["sameAddressAsCanonical"] = same_payload == "true"
    failures = [case["id"] for case in cases if case["actualAccepted"] != case["expectedAccepted"]]
    record = {"method": "Production parser/equality plus independent strict Bech32m encoder and padding decoder; bounded path and search-limit parsing.", "probeSHA256": hashlib.sha256(probe.read_bytes()).hexdigest(), "cases": cases, "caseCount": len(cases), "mismatches": failures, "argon2Calls": 0, "walletDerivationCalls": 0, "networkCalls": 0, "outcome": "failed" if failures else "passed"}
    output.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({key: record[key] for key in ["caseCount", "mismatches", "argon2Calls", "walletDerivationCalls", "networkCalls", "outcome"]}))
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
