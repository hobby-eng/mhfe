#!/usr/bin/env python3
"""AUD-008: independent BIP39/BIP32/address arithmetic and no-Argon2 API cases.

The only elliptic-curve dependency is installed cryptography/OpenSSL, independent of
Rust's k256. Hashes, paths, point addition, Keccak and address decoding are implemented
here. Expected addresses are public literals retained in src/wallet.rs, supplemented
with independently generated boundary and malformed inputs. Never supplies Argon2.
"""

import argparse
import hashlib
import hmac
import json
import re
import subprocess
import unicodedata
from pathlib import Path

import cryptography
from cryptography.hazmat.primitives.asymmetric import ec

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MASK = 2**64 - 1
BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
RIPPLE58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
ABANDON = "abandon " * 11 + "about"
COINS = {
    "Bitcoin": "bitcoin", "Ethereum": "ethereum", "Xrp": "xrp", "Tron": "tron",
    "Zcash": "zcash", "Dogecoin": "dogecoin", "BitcoinCash": "bitcoin-cash",
    "Litecoin": "litecoin", "EthereumClassic": "ethereum-classic", "Cosmos": "cosmos",
    "Injective": "injective", "Dash": "dash",
}
# Keccak-f[1600] round constants and lane rotations; Ethereum uses Keccak,
# whose domain byte is 0x01 rather than SHA3's 0x06.
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
       41, 45, 15, 21, 8, 18, 2, 61, 56, 14]


def sha(data):
    return hashlib.sha256(data).digest()


def hash160(data):
    return hashlib.new("ripemd160", sha(data)).digest()


def keccak(data):
    def rol(value, amount):
        return ((value << amount) | (value >> (64 - amount))) & MASK

    padded = bytearray(data)
    padded.append(1)
    padded.extend(b"\0" * ((136 - len(padded) % 136) % 136))
    padded[-1] |= 0x80
    state = [0] * 25
    for offset in range(0, len(padded), 136):
        for lane in range(17):
            state[lane] ^= int.from_bytes(padded[offset + lane * 8:offset + lane * 8 + 8], "little")
        for constant in RC:
            columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
                       for x in range(5)]
            for x in range(5):
                delta = columns[(x - 1) % 5] ^ rol(columns[(x + 1) % 5], 1)
                for y in range(5):
                    state[x + y * 5] ^= delta
            moved = [0] * 25
            for x in range(5):
                for y in range(5):
                    moved[y + 5 * ((2 * x + 3 * y) % 5)] = rol(state[x + 5 * y], ROT[x + 5 * y])
            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] = moved[x + 5 * y] ^ (
                        (~moved[(x + 1) % 5 + 5 * y]) & moved[(x + 2) % 5 + 5 * y]
                    )
            state[0] ^= constant
    return b"".join(value.to_bytes(8, "little") for value in state)[:32]


def point(scalar):
    numbers = ec.derive_private_key(scalar, ec.SECP256K1()).public_key().public_numbers()
    return numbers.x, numbers.y


def compressed(scalar):
    x, y = point(scalar)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def add(left, right):
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        assert y1 == y2 and y1 != 0
        slope = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def master(phrase, passphrase):
    seed = hashlib.pbkdf2_hmac("sha512", unicodedata.normalize("NFKD", phrase).encode(),
                              b"mnemonic" + unicodedata.normalize("NFKD", passphrase).encode(), 2048)
    digest = hmac.digest(b"Bitcoin seed", seed, "sha512")
    return int.from_bytes(digest[:32], "big"), digest[32:]


def derive(phrase, passphrase, path):
    scalar, chain = master(phrase, passphrase)
    for step in path.split("/")[1:]:
        hardened = step[-1] in "'h"
        index = int(step[:-1] if hardened else step) | ((1 << 31) if hardened else 0)
        parent = b"\0" + scalar.to_bytes(32, "big") if hardened else compressed(scalar)
        digest = hmac.digest(chain, parent + index.to_bytes(4, "big"), "sha512")
        delta = int.from_bytes(digest[:32], "big")
        assert delta < N
        scalar, chain = (scalar + delta) % N, digest[32:]
        assert scalar
    return scalar


def polymod(values, generators, width):
    check = 1
    for value in values:
        top = check >> width
        check = ((check & ((1 << width) - 1)) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                check ^= generator
    return check


def hrp_expand(hrp):
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def bech_encode(hrp, groups, variant):
    check = polymod(hrp_expand(hrp) + groups + [0] * 6,
                    [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3], 25) ^ variant
    return hrp + "1" + "".join(BECH[value] for value in groups +
                                [(check >> (5 * (5 - index))) & 31 for index in range(6)])


def bech_groups(text):
    assert text.lower() == text or text.upper() == text
    hrp, rest = text.lower().rsplit("1", 1)
    values = [BECH.index(char) for char in rest]
    check = polymod(hrp_expand(hrp) + values,
                    [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3], 25)
    assert check in [1, 0x2BC830A3]
    return hrp, values[:-6], check


def convert(values, source, target, pad):
    accumulator = bits = 0
    output = []
    for value in values:
        assert value < 1 << source
        accumulator = (accumulator << source) | value
        bits += source
        while bits >= target:
            bits -= target
            output.append((accumulator >> bits) & ((1 << target) - 1))
    if pad and bits:
        output.append((accumulator << (target - bits)) & ((1 << target) - 1))
    elif not pad:
        assert bits < source and (accumulator & ((1 << bits) - 1)) == 0, "noncanonical padding"
    return output


def base58_payload(text, alphabet=BASE58):
    number = 0
    for char in text:
        number = number * 58 + alphabet.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(text) - len(text.lstrip(alphabet[0]))) + raw
    assert sha(sha(raw[:-4]))[:4] == raw[-4:]
    return raw[:-4]


def program(phrase, passphrase, path, text):
    scalar = derive(phrase, passphrase, path)
    purpose = int(path.split("/")[1].rstrip("'h"))
    if purpose == 49:
        return hash160(b"\0\x14" + hash160(compressed(scalar)))
    if purpose == 86:
        x, y = point(scalar)
        internal = (x, P - y if y & 1 else y)
        tag = sha(b"TapTweak")
        tweak = int.from_bytes(sha(tag + tag + x.to_bytes(32, "big")), "big")
        assert tweak < N
        return add(internal, point(tweak))[0].to_bytes(32, "big")
    if text.startswith(("0x", "0X", "T", "inj1")):
        x, y = point(scalar)
        return keccak(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:]
    return hash160(compressed(scalar))


def decoded_program(coin, text):
    if text.startswith("0x"):
        lower = text[2:].lower()
        digest = keccak(lower.encode()).hex()
        expected = "".join(char.upper() if char in "abcdef" and int(digest[index], 16) >= 8 else char
                           for index, char in enumerate(lower))
        assert text[2:] == expected
        return bytes.fromhex(lower)
    if text.startswith("bitcoincash:"):
        prefix, data = text.split(":")
        groups = [BECH.index(char) for char in data]
        assert polymod([ord(char) & 31 for char in prefix] + [0] + groups,
                       [0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470], 35) == 1
        raw = bytes(convert(groups[:-8], 5, 8, False))
        assert raw[0] == 0 and len(raw) == 21
        return raw[1:]
    if text.startswith(("bc1", "tb1", "ltc1", "cosmos1", "inj1", "dash1", "tdash1")):
        hrp, groups, variant = bech_groups(text)
        if hrp in ["bc", "tb", "ltc"]:
            version, groups = groups[0], groups[1:]
            assert version in [0, 1] and variant == (1 if version == 0 else 0x2BC830A3)
        elif hrp in ["dash", "tdash"]:
            assert variant == 0x2BC830A3
        else:
            assert variant == 1
        raw = bytes(convert(groups, 5, 8, False))
        if hrp in ["dash", "tdash"]:
            assert raw[0] == 0xB0
            return raw[1:]
        return raw
    raw = base58_payload(text, RIPPLE58 if coin == "Xrp" else BASE58)
    prefixes = {"Bitcoin": [b"\0", b"\x05", b"\x6f", b"\xc4"], "Litecoin": [b"\x30", b"\x32"],
                "Dogecoin": [b"\x1e"], "Dash": [b"\x4c"], "Zcash": [b"\x1c\xb8"],
                "BitcoinCash": [b"\0"], "Xrp": [b"\0"], "Tron": [b"\x41"]}
    assert raw[:-20] in prefixes[coin]
    return raw[-20:]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = (args.root / "src/wallet.rs").read_text()
    retained = source.split("const ADDRESSES:", 1)[1].split("];\n", 1)[0]
    vectors = re.findall(r'Coin::(\w+),\s*"([^"]*)",\s*"([^"]*)",\s*"([^"]*)"', retained)
    assert len(vectors) == 43
    assert keccak(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    cases = []

    def address_case(name, coin, phrase, passphrase, path, text, accepted=True, match=None, accounts=4, indexes=8):
        fields = ["address", name, COINS[coin], phrase, passphrase, path, text, str(accounts), str(indexes)]
        cases.append({"input": fields, "expectedAccepted": accepted, "expectedValue": match})

    for index, (coin, passphrase, path, text) in enumerate(vectors):
        assert program(ABANDON, passphrase, path, text) == decoded_program(coin, text), (coin, path, text)
        address_case(f"retained-{index}", coin, ABANDON, passphrase, path, text, match=path)
        # Every supported coin and every retained profile is also searched by the API.
        address_case(f"search-{index}", coin, ABANDON, passphrase, "", text, match=path)
    assert set(coin for coin, _, _, _ in vectors) == set(COINS)

    for passphrase in ["", "TREZOR", "café", "cafe\u0301"]:
        scalar, _ = master(ABANDON, passphrase)
        cases.append({"input": ["fingerprint", f"fingerprint-{len(cases)}", ABANDON, passphrase],
                      "expectedAccepted": True, "expectedValue": hash160(compressed(scalar))[:4].hex()})

    for index, path in enumerate(["m", "m/0", "m/2147483647", "m/2147483647h", "m/84h/0h/0h/1/7",
                                  "M/0", " m/0", "m/", "m//0", "m/-1", "m/+1", "m/0.1",
                                  "m/2147483648", "m/4294967295", "m/0H", "m/0 h"]):
        accepted = index < 5
        cases.append({"input": ["path", f"path-{index}", path], "expectedAccepted": accepted,
                      "expectedValue": path.replace("h", "'") if accepted else ""})
    for index, (accounts, indexes, accepted) in enumerate([(1, 1, True), (0, 1, False), (1, 0, False),
                                                         (2**31, 2**31, True), (2**31 + 1, 1, False),
                                                         (1, 2**32 - 1, False)]):
        cases.append({"input": ["limit", f"limit-{index}", str(accounts), str(indexes)],
                      "expectedAccepted": accepted, "expectedValue": ""})

    # A missing retained Injective account/change/index case is supplemented independently.
    path = "m/44'/60'/3'/1/7"
    payload = program(ABANDON, "", path, "inj1")
    text = bech_encode("inj", convert(payload, 8, 5, True), 1)
    address_case("injective-account3-change-index7", "Injective", ABANDON, "", "", text, match=path)
    # Explicit maximum BIP32 indices, without attempting an unbounded search.
    path = "m/84'/0'/2147483647'/1/2147483647"
    payload = program(ABANDON, "", path, "bc1")
    text = bech_encode("bc", [0] + convert(payload, 8, 5, True), 1)
    address_case("maximum-indices", "Bitcoin", ABANDON, "", path, text, match=path)

    for coin, text, path in [
        ("Cosmos", "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4", "m/44'/118'/0'/0/0"),
        ("Injective", "inj1npvwllfr9dqr8erajqqr6s0vxnk2ak55re90dz", "m/44'/60'/0'/0/0"),
        ("Dash", "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs", "m/9'/5'/17'/0'/0'/0"),
    ]:
        hrp, groups, variant = bech_groups(text)
        address_case(f"{coin}-uppercase", coin, ABANDON, "", path, text.upper(), match=path)
        address_case(f"{coin}-mixed-case", coin, ABANDON, "", path, text[0].upper() + text[1:], False)
        address_case(f"{coin}-wrong-checksum-variant", coin, ABANDON, "", path,
                     bech_encode(hrp, groups, 1 if variant != 1 else 0x2BC830A3), False)
        for extra in [0, 1]:
            malformed = bech_encode(hrp, groups + [extra], variant)
            address_case(f"{coin}-extra-group-{extra}", coin, ABANDON, "", path, malformed, False)
        if coin == "Dash":
            for pad in [1, 2, 3]:
                malformed = bech_encode(hrp, groups[:-1] + [groups[-1] | pad], variant)
                try:
                    convert(groups[:-1] + [groups[-1] | pad], 5, 8, False)
                    raise AssertionError("negative control unexpectedly canonical")
                except AssertionError as error:
                    assert str(error) == "noncanonical padding"
                address_case(f"Dash-nonzero-padding-{pad}", coin, ABANDON, "", path, malformed, False)

    # Independent EIP-55 negative and uniform-case controls.
    eth = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    address_case("eth-lowercase", "Ethereum", ABANDON, "", "m/44'/60'/0'/0/0", eth.lower(), match="m/44'/60'/0'/0/0")
    address_case("eth-uppercase", "Ethereum", ABANDON, "", "m/44'/60'/0'/0/0", "0X" + eth[2:].upper(), match="m/44'/60'/0'/0/0")
    address_case("eth-wrong-checksum", "Ethereum", ABANDON, "", "m/44'/60'/0'/0/0", eth.replace("EfFD", "efFD"), False)
    address_case("eth-wrong-passphrase", "Ethereum", ABANDON, "TREZOR", "m/44'/60'/0'/0/0", eth)
    # Bounds are counts. The address at account3/index7 is just beyond these smaller searches.
    btc = "bc1q8r4wsa3nye5qypv80vpfg4sh99uf02u5mmh5ry"
    address_case("account-outside-limit", "Bitcoin", ABANDON, "", "", btc, accounts=3, indexes=8)
    address_case("index-outside-limit", "Bitcoin", ABANDON, "", "", btc, accounts=4, indexes=7)

    stream = "\n".join("\t".join(case["input"]) for case in cases) + "\n"
    result = subprocess.run([str(args.probe)], input=stream, text=True, capture_output=True, check=True)
    lines = result.stdout.splitlines()
    assert len(lines) == len(cases)
    mismatches = []
    for case, line in zip(cases, lines):
        mode, name, accepted, value = line.split("\t")
        assert [mode, name] == case["input"][:2]
        expected = case["expectedValue"] or ""
        case["actualAccepted"] = accepted == "true"
        case["actualValue"] = value
        if case["actualAccepted"] != case["expectedAccepted"] or value != expected:
            mismatches.append(case)
    record = {"cryptographyVersion": cryptography.__version__, "unicodeVersion": unicodedata.unidata_version,
              "walletSourceSHA256": sha(source.encode()).hex(), "probeSHA256": sha(args.probe.read_bytes()).hex(),
              "retainedVectorsIndependentlyChecked": len(vectors), "coins": list(COINS.values()),
              "argon2Calls": 0, "cases": cases, "mismatches": mismatches}
    args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({key: value for key, value in record.items() if key not in ["cases", "mismatches"]}))
    print(json.dumps({"APIcases": len(cases), "mismatches": [{"id": case["input"][1],
                     "address": case["input"][6], "expectedAccepted": case["expectedAccepted"],
                     "actualAccepted": case["actualAccepted"], "matchedPath": case["actualValue"]}
                    for case in mismatches]}))


if __name__ == "__main__":
    main()
