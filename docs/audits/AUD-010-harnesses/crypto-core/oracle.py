#!/usr/bin/env python3
"""AUD-010 crypto-core: an independent oracle for the cryptographic outputs of mhfe.

Written for this audit from the specification (mhfe_spec README.md, read only) and the public
standards it cites, without importing or copying any code of the mhfe repository, including its own
"independent" scripts. Every primitive that Python's standard library lacks is implemented here:
secp256k1, BIP32, Keccak-256, Bech32/Bech32m, Base58Check (both alphabets), CashAddr, GF(2^11)
Reed-Solomon. Argon2id comes from OpenSSL through Python `cryptography`, which is not the reference
C code that mhfe vendors.

Each check prints one line; the script exits 1 if any check fails, so it can be rerun as a gate.

    python3 oracle.py [--only NAME[,NAME...]]

Inputs: the repository's tests/fixtures, src/ constants (read as text), vendor/ files, the
specification checkout at ../mhfe_spec (read only) and the BIP39 English list and test vectors of the
bip39 3.0.0 crate in $CARGO_HOME/registry (published third-party data). Public test data only.
"""

import glob
import hashlib
import hmac
import json
import os
import re
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SPEC = ROOT.parent / "mhfe_spec"
CARGO_HOME = Path(os.environ.get("CARGO_HOME", ROOT.parent / "workingspace/cargo"))

FAILURES = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"{status} {name}" + (f": {detail}" if detail else ""), flush=True)
    if not condition:
        FAILURES.append(name)
    return condition


# ---------------------------------------------------------------------------------------------
# BIP39 word list and coding


def bip39_crate_dir():
    found = sorted(glob.glob(str(CARGO_HOME / "registry/src/*/bip39-3.0.0")))
    if not found:
        sys.exit("bip39-3.0.0 sources not found under CARGO_HOME")
    return Path(found[0])


WORDS = re.findall(r'"([a-z]+)"', (bip39_crate_dir() / "src/language/english.rs").read_text())
WORD_INDEX = {word: index for index, word in enumerate(WORDS)}
# SHA-256 of english.txt of bitcoin/bips bip-0039 (each word followed by LF).
BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


def entropy_to_words(entropy):
    bits = len(entropy) * 8
    checksum_bits = bits // 32
    value = int.from_bytes(entropy, "big") << checksum_bits
    value |= hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    count = (bits + checksum_bits) // 11
    return " ".join(WORDS[(value >> (11 * (count - 1 - i))) & 0x7FF] for i in range(count))


def words_to_entropy(phrase):
    words = phrase.split(" ")
    assert len(words) in (12, 15, 18, 21, 24), "word count"
    value = 0
    for word in words:
        value = (value << 11) | WORD_INDEX[word]
    total = 11 * len(words)
    checksum_bits = total // 33
    entropy = (value >> checksum_bits).to_bytes((total - checksum_bits) // 8, "big")
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    if value & ((1 << checksum_bits) - 1) != expected:
        raise ValueError("checksum")
    return entropy


def bip39_seed(phrase, passphrase):
    password = unicodedata.normalize("NFKD", phrase).encode()
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    return hashlib.pbkdf2_hmac("sha512", password, salt, 2048, 64)


def trezor_vectors():
    """(entropy, phrase, seed) of the bip39 3.0.0 crate's test_vectors_english (trezor vectors)."""
    source = (bip39_crate_dir() / "src/lib.rs").read_text()
    start = source.index("fn test_vectors_english")
    block = source[start : source.index("];", start)]
    triples = re.findall(r'\(\s*"([0-9a-f]+)",\s*"([a-z ]+)",\s*"([0-9a-f]+)",\s*\)', block)
    return [(bytes.fromhex(e), p, s) for e, p, s in triples]


# ---------------------------------------------------------------------------------------------
# secp256k1 and BIP32

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (slope * slope - a[0] - b[0]) % P
    return (x, (slope * (a[0] - x) - a[1]) % P)


def point_mul(k, point=G):
    result = None
    while k:
        if k & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        k >>= 1
    return result


def compressed(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def uncompressed(point):
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


HARD = 1 << 31


def bip32_master(seed):
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = int.from_bytes(digest[:32], "big")
    assert 0 < key < N
    return key, digest[32:]


def bip32_child(key, chain, index):
    if index >= HARD:
        data = b"\x00" + key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = compressed(point_mul(key)) + index.to_bytes(4, "big")
    digest = hmac.new(chain, data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    assert tweak < N
    child = (tweak + key) % N
    assert child != 0
    return child, digest[32:]


def parse_path(text):
    steps = []
    for step in text.split("/")[1:]:
        steps.append(int(step[:-1]) | HARD if step.endswith("'") else int(step))
    return steps


def derive(seed, path):
    key, chain = bip32_master(seed)
    for index in parse_path(path) if isinstance(path, str) else path:
        key, chain = bip32_child(key, chain, index)
    return key, chain


def ripemd160(data):
    return hashlib.new("ripemd160", data).digest()


def hash160(data):
    return ripemd160(hashlib.sha256(data).digest())


def fingerprint(phrase, passphrase):
    key, _ = bip32_master(bip39_seed(phrase, passphrase))
    return hash160(compressed(point_mul(key)))[:4].hex()


# ---------------------------------------------------------------------------------------------
# Keccak-256 (the original padding, as Ethereum uses), checked against hashlib's SHA3-256


def _keccak_constants():
    def rc_bit(t):
        if t % 255 == 0:
            return 1
        register = 1
        for _ in range(t % 255):
            register <<= 1
            if register & 0x100:
                register ^= 0x171
        return register & 1

    round_constants = [
        sum(rc_bit(j + 7 * i) << ((1 << j) - 1) for j in range(7)) for i in range(24)
    ]
    rotations = [[0] * 5 for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        rotations[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return round_constants, rotations


KECCAK_RC, KECCAK_ROT = _keccak_constants()
MASK64 = (1 << 64) - 1


def _rol(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & MASK64 if shift else value


def _keccak_f(lanes):
    a = [[lanes[x + 5 * y] for y in range(5)] for x in range(5)]
    for rc in KECCAK_RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], KECCAK_ROT[x][y])
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & MASK64 & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return [a[i % 5][i // 5] for i in range(25)]


def keccak256(data, domain=0x01):
    rate = 136
    padded = bytearray(data) + bytes([domain])
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    lanes = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            lanes[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        lanes = _keccak_f(lanes)
    return b"".join(lane.to_bytes(8, "little") for lane in lanes[:4])


# ---------------------------------------------------------------------------------------------
# Address encodings

B58_BITCOIN = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_RIPPLE = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def base58check(payload, alphabet=B58_BITCOIN):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    value = int.from_bytes(data, "big")
    text = ""
    while value:
        value, digit = divmod(value, 58)
        text = alphabet[digit] + text
    zeros = len(data) - len(data.lstrip(b"\x00"))
    return alphabet[0] * zeros + text


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST, BECH32M_CONST = 1, 0x2BC830A3


def _bech32_polymod(values):
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            checksum ^= generators[i] if (top >> i) & 1 else 0
    return checksum


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_encode(hrp, data, constant):
    polymod = _bech32_polymod(_hrp_expand(hrp) + data + [0] * 6) ^ constant
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in data + checksum)


def bech32_verify(text):
    """The constant of a valid Bech32/Bech32m string, or None."""
    if text.lower() != text and text.upper() != text:
        return None
    text = text.lower()
    hrp, _, data = text.rpartition("1")
    values = [BECH32_CHARSET.find(c) for c in data]
    if not hrp or -1 in values or len(values) < 6:
        return None
    constant = _bech32_polymod(_hrp_expand(hrp) + values)
    return constant if constant in (BECH32_CONST, BECH32M_CONST) else None


def convert_bits(data, source, target, pad=True):
    accumulator, bits, out = 0, 0, []
    for value in data:
        accumulator = (accumulator << source) | value
        bits += source
        while bits >= target:
            bits -= target
            out.append((accumulator >> bits) & ((1 << target) - 1))
    if pad and bits:
        out.append((accumulator << (target - bits)) & ((1 << target) - 1))
    return out


def segwit_address(hrp, version, program):
    constant = BECH32_CONST if version == 0 else BECH32M_CONST
    return bech32_encode(hrp, [version] + convert_bits(program, 8, 5), constant)


def _cashaddr_polymod(values):
    generators = [0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470]
    checksum = 1
    for value in values:
        top = checksum >> 35
        checksum = ((checksum & 0x07FFFFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                checksum ^= generators[i]
    return checksum ^ 1


def cashaddr(hash20, prefix="bitcoincash", version_byte=0):
    payload = convert_bits(bytes([version_byte]) + hash20, 8, 5)
    polymod = _cashaddr_polymod([ord(c) & 31 for c in prefix] + [0] + payload + [0] * 8)
    checksum = [(polymod >> 5 * (7 - i)) & 31 for i in range(8)]
    return prefix + ":" + "".join(BECH32_CHARSET[d] for d in payload + checksum)


def eip55(hash20):
    lowercase = hash20.hex()
    digest = keccak256(lowercase.encode()).hex()
    return "0x" + "".join(c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(lowercase))


def tagged_hash(tag, data):
    tag_digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_digest + tag_digest + data).digest()


def taproot_output(key):
    point = point_mul(key)
    if point[1] & 1:
        point = (point[0], P - point[1])
    tweak = int.from_bytes(tagged_hash("TapTweak", point[0].to_bytes(32, "big")), "big")
    assert tweak < N
    output = point_add(point, point_mul(tweak))
    return output[0].to_bytes(32, "big")


def address_for(coin, path, key, legacy=False):
    """The single-key receiving address of `coin` whose type the path's purpose selects; `legacy`
    asks for the Base58 form of a Bitcoin Cash address."""
    point = point_mul(key)
    pub = compressed(point)
    purpose = parse_path(path)[0] & ~HARD
    testnet = len(parse_path(path)) > 1 and parse_path(path)[1] == 1 | HARD and coin == "bitcoin"
    keccak20 = keccak256(uncompressed(point)[1:])[12:]
    if coin in ("bitcoin", "litecoin"):
        if purpose == 44:
            version = {"bitcoin": 0x6F if testnet else 0x00, "litecoin": 0x30}[coin]
            return base58check(bytes([version]) + hash160(pub))
        if purpose == 49:
            script_hash = hash160(b"\x00\x14" + hash160(pub))
            version = {"bitcoin": 0xC4 if testnet else 0x05, "litecoin": 0x32}[coin]
            return base58check(bytes([version]) + script_hash)
        hrp = {"bitcoin": "tb" if testnet else "bc", "litecoin": "ltc"}[coin]
        if purpose == 84:
            return segwit_address(hrp, 0, hash160(pub))
        if purpose == 86 and coin == "bitcoin":
            return segwit_address(hrp, 1, taproot_output(key))
        raise ValueError(path)
    if coin in ("ethereum", "ethereum-classic"):
        return eip55(keccak20)
    if coin == "xrp":
        return base58check(b"\x00" + hash160(pub), B58_RIPPLE)
    if coin == "tron":
        return base58check(b"\x41" + keccak20)
    if coin == "zcash":
        return base58check(b"\x1c\xb8" + hash160(pub))
    if coin == "dogecoin":
        return base58check(b"\x1e" + hash160(pub))
    if coin == "bitcoin-cash":
        return base58check(b"\x00" + hash160(pub)) if legacy else cashaddr(hash160(pub))
    if coin == "cosmos":
        return bech32_encode("cosmos", convert_bits(hash160(pub), 8, 5), BECH32_CONST)
    if coin == "injective":
        return bech32_encode("inj", convert_bits(keccak20, 8, 5), BECH32_CONST)
    if coin == "dash":
        if purpose == 9:
            # DIP18 Platform payment address: Bech32m, type byte 0xb0 and HASH160.
            return bech32_encode("dash", convert_bits(b"\xb0" + hash160(pub), 8, 5), BECH32M_CONST)
        return base58check(b"\x4c" + hash160(pub))
    raise ValueError(coin)


# ---------------------------------------------------------------------------------------------
# MHFE suites 3 and 4 (specification "Permutation" and "Suite 4")


def be32(value):
    return value.to_bytes(4, "big")


def memory_kib(level):
    return (2 + level % 2) << (20 + level // 2)


def openssl_argon2id(password, salt, kib, passes, lanes=4, secret=None, ad=None):
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

    return Argon2id(
        salt=salt, length=32, iterations=passes, lanes=lanes, memory_cost=kib, secret=secret, ad=ad
    ).derive(password)


def mhfe_perm(state, password, pim, level, argon2, suite, inverse=False, trace=None):
    suite_id = b"MHFE-BIP39-256-EXPERIMENTAL-3" if suite == 3 else b"MHFE-BIP39-LP-EXPERIMENTAL-4"
    half = len(state) // 2
    ent = b"" if suite == 3 else be32(8 * len(state))
    left, right = state[:half], state[half:]

    def mask(index, r):
        message = be32(level) + be32(pim) + ent + be32(index) + r
        salt = hashlib.blake2b(suite_id + b"/ROUND-SALT" + message, digest_size=32).digest()[:16]
        key = argon2(password, salt)
        value = hmac.new(key, suite_id + b"/ROUND-MASK" + message, hashlib.sha256).digest()[:half]
        if trace is not None:
            trace.append((index, salt, key, value))
        return value

    if not inverse:
        for index in range(12):
            left, right = right, bytes(a ^ b for a, b in zip(left, mask(index, right)))
    else:
        for index in reversed(range(12)):
            left, right = bytes(a ^ b for a, b in zip(right, mask(index, left))), left
    return left + right


def pack(entropy):
    return entropy + hashlib.sha256(entropy).digest()[: 32 - len(entropy)]


def detect(x):
    matches = [
        words
        for words, size in ((12, 16), (15, 20), (18, 24), (21, 28))
        if hashlib.sha256(x[:size]).digest()[: 32 - size] == x[size:]
    ]
    readings = [(w, True, entropy_to_words(x[: {12: 16, 15: 20, 18: 24, 21: 28}[w]])) for w in matches]
    if len(matches) == 1:
        return readings
    return readings + [(24, False, entropy_to_words(x))]


def nfkd_password(text):
    return unicodedata.normalize("NFKD", text).encode()


# ---------------------------------------------------------------------------------------------
# GF(2^11) Reed-Solomon (MHFE-REPAIR-1)

GF_EXP = [0] * 4094
GF_LOG = [0] * 2048
_value = 1
for _power in range(2047):
    GF_EXP[_power] = GF_EXP[_power + 2047] = _value
    GF_LOG[_value] = _power
    _value <<= 1
    if _value & 0x800:
        _value ^= 0x805


def gf_mul(a, b):
    return 0 if a == 0 or b == 0 else GF_EXP[GF_LOG[a] + GF_LOG[b]]


def gf_inv(a):
    return GF_EXP[2047 - GF_LOG[a]]


def rs_generator(k):
    poly = [1]
    for power in range(1, k + 1):
        root = GF_EXP[power]
        poly = [(poly[i] if i < len(poly) else 0) ^ (gf_mul(poly[i - 1], root) if i else 0) for i in range(len(poly) + 1)]
    return poly


def poly_mod(dividend, divisor):
    """Remainder of polynomial division, highest degree first, monic divisor."""
    remainder = list(dividend)
    for i in range(len(dividend) - len(divisor) + 1):
        coefficient = remainder[i]
        if coefficient:
            for j in range(1, len(divisor)):
                remainder[i + j] ^= gf_mul(divisor[j], coefficient)
    return remainder[-(len(divisor) - 1) :]


def repair_words(container, k):
    data = [WORD_INDEX[w] for w in container.split()]
    parity = poly_mod(data + [0] * k, rs_generator(k))
    return " ".join(WORDS[v] for v in parity)


def rs_syndromes(codeword, k):
    out = []
    for power in range(1, k + 1):
        x, total = GF_EXP[power], 0
        for symbol in codeword:
            total = gf_mul(total, x) ^ symbol
        out.append(total)
    return out


def rs_solve(received, positions, k):
    """Error values at `positions` by Gaussian elimination on the k syndrome equations."""
    n = len(received)
    syndromes = rs_syndromes(received, k)
    unknowns = len(positions)
    rows = []
    for j in range(k):
        rows.append([GF_EXP[((n - 1 - p) * (j + 1)) % 2047] for p in positions] + [syndromes[j]])
    pivot_row = 0
    for column in range(unknowns):
        pivot = next((r for r in range(pivot_row, k) if rows[r][column]), None)
        if pivot is None:
            return None
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        inverse = gf_inv(rows[pivot_row][column])
        rows[pivot_row] = [gf_mul(v, inverse) for v in rows[pivot_row]]
        for r in range(k):
            if r != pivot_row and rows[r][column]:
                factor = rows[r][column]
                rows[r] = [a ^ gf_mul(factor, b) for a, b in zip(rows[r], rows[pivot_row])]
        pivot_row += 1
    if any(rows[r][-1] for r in range(unknowns, k)):
        return None
    corrected = list(received)
    for i, p in enumerate(positions):
        corrected[p] ^= rows[i][-1]
    return corrected if not any(rs_syndromes(corrected, k)) else None


def rs_decode(received, erased, k):
    from itertools import combinations

    readable = [p for p in range(len(received)) if p not in erased]
    for wrong in range((k - len(erased)) // 2 + 1):
        for chosen in combinations(readable, wrong):
            result = rs_solve(received, sorted(erased + list(chosen)), k)
            if result is not None:
                return result
    return None


# ---------------------------------------------------------------------------------------------
# Checks


def check_wordlist_and_bip39():
    listing = ("\n".join(WORDS) + "\n").encode()
    check("bip39.wordlist-sha256", len(WORDS) == 2048 and hashlib.sha256(listing).hexdigest() == BIP39_ENGLISH_SHA256)
    vectors = trezor_vectors()
    check("bip39.trezor-vector-count", len(vectors) == 24, str(len(vectors)))
    ok = all(entropy_to_words(e) == p and words_to_entropy(p) == e for e, p, _ in vectors)
    check("bip39.trezor-entropy-words-both-ways", ok)
    ok = all(bip39_seed(p, "TREZOR").hex() == s for _, p, s in vectors)
    check("bip39.trezor-seeds-pbkdf2", ok)
    # mhfe's own copies of the vectors (phrase known answers and wallet seed table) must match.
    phrase_ka = (ROOT / "src/phrase/known_answers.rs").read_text()
    pairs = re.findall(r'entropy: "([0-9a-f]+)",\s*phrase: "([a-z ]+)"', phrase_ka)
    check(
        "bip39.mhfe-trezor-table-equals-published",
        [(bytes.fromhex(e), p) for e, p in pairs] == [(e, p) for e, p, _ in vectors],
    )
    wallet_ka = (ROOT / "src/wallet/known_answers.rs").read_text()
    table = wallet_ka[wallet_ka.index("const TREZOR_SEEDS") :]
    seeds = re.findall(r'"([0-9a-f]{128})"', table[: table.index("];")])
    check("bip39.mhfe-trezor-seeds-equal-published", seeds == [s for _, _, s in vectors])
    # Edge entropies: all zero and all 0xff at every width round-trip; leading-zero entropy.
    edges = [bytes([b]) * n for n in (16, 20, 24, 28, 32) for b in (0, 0xFF)]
    edges += [bytes(15) + b"\x01", b"\x00\x00\x01" + bytes(29)]
    check("bip39.edge-entropies-round-trip", all(words_to_entropy(entropy_to_words(e)) == e for e in edges))
    # The NFKD passphrase case of the wallet known answers (Python's own NFKD, Unicode 16).
    passphrase = "Café ﬁ ＰÅ① \U0001f510 \u0439"
    seed = bip39_seed("abandon " * 11 + "about", passphrase).hex()
    check("bip39.nfkd-passphrase-seed", seed in wallet_ka.replace("\\\n", "").replace(" ", ""), seed[:16])
    check("bip32.fingerprint-abandon", fingerprint("abandon " * 11 + "about", "") == "73c5da0a")
    trezor_fp = fingerprint("abandon " * 11 + "about", "TREZOR")
    check("bip32.fingerprint-abandon-trezor", trezor_fp == "b4e3f5ed", trezor_fp)


def check_bip32_vectors():
    # BIP-0032 test vector 1, m/0H/1/2H/2/1000000000, and vector 3 m/0H (leading zero).
    key, chain = bip32_master(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    ok = key == 0xE8F32E723DECF4051AEFAC8E2C93C9C5B214313817CDB01A1494B917C8436B35
    ok &= chain.hex() == "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    ok &= hash160(compressed(point_mul(key)))[:4].hex() == "3442193e"
    key, chain = derive(bytes.fromhex("000102030405060708090a0b0c0d0e0f"), [HARD, 1, 2 | HARD, 2, 1000000000])
    ok &= key == 0x471B76E389E528D6DE6D816857E012C5455051CAD6660850E58372A6C3E6E7C8
    ok &= chain.hex() == "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"
    ok &= compressed(point_mul(key)).hex() == "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"
    check("bip32.vector-1", ok)
    seed3 = bytes.fromhex(
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
    )
    key, chain = bip32_master(seed3)
    ok = key.to_bytes(32, "big").hex() == "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32"
    key, chain = bip32_child(key, chain, HARD)
    ok &= key.to_bytes(32, "big").hex() == "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef"
    check("bip32.vector-3-leading-zero", ok)


def check_primitives():
    check("keccak.matches-sha3-with-sha3-padding", all(
        keccak256(m, 0x06) == hashlib.sha3_256(m).digest() for m in (b"", b"abc", bytes(range(200)), b"x" * 136, b"y" * 135)
    ))
    check("keccak.empty", keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    # BIP173 / BIP350 valid strings and the CashAddr specification's example.
    check("bech32.bip173-valid", bech32_verify("A12UEL5L") == BECH32_CONST)
    check("bech32.bip350-valid", bech32_verify("A1LQFN3A") == BECH32M_CONST)
    check(
        "cashaddr.spec-example",
        cashaddr(bytes.fromhex("76a04053bda0a88bda5177b86a15c3b29f559873")) == "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    )
    check("base58.bip84-legacy", base58check(b"\x00" + bytes(20)) == "1111111111111111111114oLvT2")
    # RFC 9106 section 5.3 Argon2id test vector through OpenSSL.
    tag = openssl_argon2id(bytes([1]) * 32, bytes([2]) * 16, 32, 3, 4, bytes([3]) * 8, bytes([4]) * 12)
    check("argon2.openssl-rfc9106", tag.hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    # The engine's own startup/full Argon2 known answers (src/engine/known_answers.rs).
    source = (ROOT / "src/engine/known_answers.rs").read_text()
    for kib, passes, expected in re.findall(
        r"memory_kib: ([0-9_* ]+),\s*passes: (\d+),\s*\},\s*tag: hex\(\"([0-9a-f]{64})\"\)", source
    ):
        kib_value = 1
        for factor in kib.replace("_", "").split("*"):  # "64 * 1024" style literal in the source
            kib_value *= int(factor)
        if kib_value > 256 * 1024:
            continue
        got = openssl_argon2id(b"public test password", b"0123456789abcdef", kib_value, int(passes))
        check(f"argon2.engine-known-answer-{kib_value}KiB-t{passes}", got.hex() == expected)


def published_vectors():
    out = []
    for folder, suite in (("suite3-vectors", 3), ("suite4-vectors", 4)):
        for path in sorted((ROOT / "tests/fixtures" / folder).glob("*.json")):
            data = json.loads(path.read_text())
            if isinstance(data, dict) and data.get("schema", "").endswith(("vector-v2", "vector-v1")) and "encryption" in data:
                out.append((suite, path.name, data))
    return out


def check_published_vectors():
    vectors = published_vectors()
    check("vectors.count", [s for s, _, _ in vectors].count(3) == 17 and [s for s, _, _ in vectors].count(4) == 10, str(len(vectors)))
    for suite, name, v in vectors:
        inputs = v["inputs"]
        pim, level = inputs["pim"], inputs["memory_level"]
        password = nfkd_password(inputs["password"])
        keys = {}
        for direction in ("encryption", "decryption"):
            for r in v[direction]["rounds"]:
                keys[r["salt_hex"]] = bytes.fromhex(r["argon2_key_hex"])
        argon2 = lambda pw, salt: keys[salt.hex()] if pw == password else None
        ok = password.hex() == inputs["password_nfkd_utf8_hex"]
        ok &= v["argon2"]["memory_kib"] == memory_kib(level) and v["argon2"]["passes"] == 12 * (pim + 1)
        ok &= v["argon2"]["lanes"] == 4 and v["argon2"]["version"] == 0x13
        entropy = words_to_entropy(inputs["phrase"])
        x = pack(entropy) if suite == 3 else entropy
        trace = []
        y = mhfe_perm(x, password, pim, level, argon2, suite, trace=trace)
        ok &= entropy_to_words(y) == v["container"]
        ok &= [(t[0], t[1].hex(), t[3].hex()) for t in trace] == [
            (r["round"], r["salt_hex"], r["mask_hex"]) for r in v["encryption"]["rounds"]
        ]
        back_trace = []
        back = mhfe_perm(words_to_entropy(v["container"]), password, pim, level, argon2, suite, inverse=True, trace=back_trace)
        ok &= back == x
        ok &= [(t[0], t[1].hex(), t[3].hex()) for t in back_trace] == [
            (r["round"], r["salt_hex"], r["mask_hex"]) for r in v["decryption"]["rounds"]
        ]
        if suite == 3:
            ok &= [(c["words"], c["verified"], c["phrase"]) for c in v["recovery"]] == detect(back)
        else:
            ok &= len(v["container"].split()) == len(inputs["phrase"].split())
            rec = v["recovery"]
            rec = rec[0] if isinstance(rec, list) else rec
            ok &= rec["phrase"] == inputs["phrase"] and rec["verified"] is False
        check(f"vectors.suite{suite}.{name}", ok)


def check_published_rounds_table():
    """src/mhfe/published_rounds.rs equals the fixtures: inputs, container, recovery, salts, keys."""
    source = (ROOT / "src/mhfe/published_rounds.rs").read_text()
    blocks = source.split("PublishedVector {")[1:]
    table = {}
    for block in blocks:
        name = re.search(r'name: "([^"]+)"', block).group(1)
        rounds = re.findall(r'salt: hex\("([0-9a-f]{32})"\),\s*key: hex\("([0-9a-f]{64})"\)', block)
        container = re.search(r'container: "([^"]+)"', block).group(1)
        pim = int(re.search(r"pim: (\d+)", block).group(1))
        level = int(re.search(r"memory_level: (\d+)", block).group(1))
        table[name] = (rounds, container, pim, level)
    ok = True
    vectors = published_vectors()
    for suite, file_name, v in vectors:
        name = file_name[:-5]
        rounds, container, pim, level = table.get(name, (None, None, None, None))
        expected = [(r["salt_hex"], r["argon2_key_hex"]) for r in v["encryption"]["rounds"]]
        same = rounds == expected and container == v["container"]
        same &= (pim, level) == (v["inputs"]["pim"], v["inputs"]["memory_level"])
        if not same:
            print(f"  published_rounds.rs differs for {name}")
        ok &= same
    check("published-rounds.table-equals-fixtures", ok and len(table) == len(vectors), f"{len(table)} entries")


def check_reduced_cost_containers():
    """REDUCED_COST_CONTAINER and its suite 4 twin: Argon2id 256 KiB, 1 pass, 4 lanes, settings 0."""
    source = (ROOT / "src/mhfe.rs").read_text()

    def constant(name):
        text = re.search(name + r': &str =\s*((?:"(?:[^"\\]|\\\n)*"\s*)+);', source).group(1)
        return " ".join(re.sub(r"\\\n\s*", "", text).strip('"').split())

    argon2 = lambda pw, salt: openssl_argon2id(pw, salt, 256, 1)
    password = nfkd_password("public test password")
    zero12 = bytes(16)
    y3 = mhfe_perm(pack(zero12), password, 0, 0, argon2, 3)
    y4 = mhfe_perm(zero12, password, 0, 0, argon2, 4)
    check("reduced-cost.suite3", entropy_to_words(y3) == constant("REDUCED_COST_CONTAINER"), entropy_to_words(y3))
    check("reduced-cost.suite4", entropy_to_words(y4) == constant("REDUCED_COST_SAME_LENGTH_CONTAINER"), entropy_to_words(y4))
    browsers = (ROOT / "scripts/verify-browsers.mjs").read_text()
    check("reduced-cost.verify-browsers-uses-same", entropy_to_words(y3) in " ".join(browsers.split()) and entropy_to_words(y4) in browsers)
    # Wrong password: another valid phrase of the same length, which re-encrypts to the container.
    wrong = nfkd_password("public test passwore")
    other4 = mhfe_perm(y4, wrong, 0, 0, argon2, 4, inverse=True)
    check("reduced-cost.suite4-wrong-password-is-a-decoy", other4 != zero12 and mhfe_perm(other4, wrong, 0, 0, argon2, 4) == y4)
    other3 = mhfe_perm(y3, wrong, 0, 0, argon2, 3, inverse=True)
    check("reduced-cost.suite3-wrong-password-reads-unverified-24", detect(other3)[-1][0] == 24 and len(detect(other3)) == 1)


def check_repair_words():
    spec_g = {
        2: [1, 6, 8],
        4: [1, 30, 216, 960, 1024],
        6: [1, 126, 1181, 1719, 2029, 1077, 1034],
        8: [1, 510, 1509, 1770, 1837, 850, 1339, 600, 680],
    }
    check("repair.generator-coefficients", all(rs_generator(k) == g for k, g in spec_g.items()))
    zero12 = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())["container"]
    nonzero12 = json.loads((ROOT / "tests/fixtures/suite4-vectors/same-length-nonzero-12.json").read_text())["container"]
    nonzero21 = json.loads((ROOT / "tests/fixtures/suite4-vectors/same-length-nonzero-21.json").read_text())["container"]
    art = "abandon " * 23 + "art"
    spec = (SPEC / "vectors/profiles/README.md").read_text()
    rows = re.findall(r"\| `[^|]+` +\| `([a-z ]+)` / `([a-z ]+)` / `([a-z ]+)` / `([a-z ]+)` +\|", spec)
    containers = [zero12, nonzero12, nonzero21, art.strip()]
    ok = len(rows) == 4
    for container, row in zip(containers, rows):
        ok &= [repair_words(container, k) for k in (2, 4, 6, 8)] == list(row)
    check("repair.spec-profile-vectors", ok)
    # The spec's three repair cases with the four repair words of zero-12.
    card = repair_words(zero12, 4).split()
    plate = zero12.split()
    codeword = [WORD_INDEX[w] for w in plate + card]
    cases = [
        ({2: None, 16: None}, ["tower", "cycle"]),
        ({9: "zoo", 4: None}, ["rib", "iron"]),
        ({2: "zoo", 16: "abandon"}, ["tower", "cycle"]),
    ]
    ok = True
    for damage, restored in cases:
        received = list(codeword)
        erased = []
        for position, word in damage.items():
            if word is None:
                received[position] = 0
                erased.append(position)
            else:
                received[position] = WORD_INDEX[word]
        decoded = rs_decode(received, erased, 4)
        ok &= decoded == codeword and [plate[p] for p in sorted(damage)] == sorted(restored, key=lambda w: plate.index(w))
    check("repair.spec-repair-cases-independent-decoder", ok)
    # The repair vectors that mhfe carries in its known answers must be the spec's.
    known = (ROOT / "src/repair/known_answers.rs").read_text()
    check("repair.mhfe-known-answers-carry-spec-words", all(words in known for row in rows for words in row))


def check_check_word_and_eff():
    path = ROOT / "vendor/eff-large-wordlist/eff_large_wordlist.txt"
    raw = path.read_bytes()
    check("eff.sha256-pinned", hashlib.sha256(raw).hexdigest() == "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e")
    lines = raw.decode().splitlines()
    dice = [line.split("\t")[0] for line in lines]
    words = [line.split("\t")[1] for line in lines]
    expected_dice = ["".join(str(1 + (i // 6**p) % 6) for p in range(4, -1, -1)) for i in range(7776)]
    check("eff.dice-order", dice == expected_dice and len(set(words)) == 7776)
    spec = (SPEC / "vectors/profiles/README.md").read_text()
    rows = re.findall(r"\| `(\d{5} \d{5} \d{5} \d{5} \d{5})` +\| (\d+) +\| `([a-z -]+)` +\|", spec)
    ok = len(rows) == 4
    for rolls, index, password in rows:
        drawn = [expected_dice.index(r) for r in rolls.split()]
        c = (drawn[0] + 5 * drawn[1] + 7 * drawn[2] + 11 * drawn[3] + 13 * drawn[4]) % 7776
        ok &= c == int(index) and " ".join(words[d] for d in drawn + [c]) == password
    check("check-word.spec-vectors", ok)
    ka = (ROOT / "src/check_word/known_answers.rs").read_text()
    check("check-word.mhfe-known-answers-carry-spec-passwords", all(p in ka for _, _, p in rows))


def check_wallet_check():
    spec = (SPEC / "vectors/profiles/README.md").read_text()
    rows = re.findall(r"\| (\d+) +\| (`TREZOR`|empty string) +\| `([0-9a-f]{64})` \|", spec)
    ok = len(rows) == 2
    for counter, passphrase, digest in rows:
        passphrase = "TREZOR" if passphrase == "`TREZOR`" else ""
        entropy = bytes(24) + int(counter).to_bytes(8, "big")
        seed = bip39_seed(entropy_to_words(entropy), passphrase)
        t = hashlib.sha256(b"MHFE-WALLET-CHECK-SEED-1" + be32(256) + seed).digest()
        ok &= t.hex() == digest and t[:2] == b"\x00\x00"
    check("wallet-check.spec-vectors", ok)
    # The negative rows the specification states.
    def t_of(counter, passphrase, with_bits=True):
        seed = bip39_seed(entropy_to_words(bytes(24) + counter.to_bytes(8, "big")), passphrase)
        return hashlib.sha256(b"MHFE-WALLET-CHECK-SEED-1" + (be32(256) if with_bits else b"") + seed).hexdigest()
    ok = t_of(76562, "").startswith("ebd07f71") and t_of(98918, "TREZOR").startswith("8d2b97fb")
    ok &= t_of(76562, "TREZOR", with_bits=False).startswith("f2c9f765")
    check("wallet-check.spec-negative-rows", ok)
    ka = (ROOT / "src/wallet_check/known_answers.rs").read_text()
    check("wallet-check.mhfe-known-answers-carry-spec-digests", all(d in ka for _, _, d in rows))
    # src/hidden/known_answers.rs: the zero-24 wallet's digest without a passphrase begins 49f67bdf.
    seed = bip39_seed(entropy_to_words(bytes(32)), "")
    zero24 = hashlib.sha256(b"MHFE-WALLET-CHECK-SEED-1" + be32(256) + seed).hexdigest()
    check("wallet-check.zero-24-digest-49f67bdf", zero24.startswith("49f67bdf"), zero24[:8])


def wallet_address_table():
    """(coin, passphrase, path, address) rows of src/wallet/known_answers.rs ADDRESSES."""
    source = (ROOT / "src/wallet/known_answers.rs").read_text()
    body = source[source.index("const ADDRESSES") : source.index("const DAMAGED")]
    coin_ids = {
        "Bitcoin": "bitcoin", "Ethereum": "ethereum", "Xrp": "xrp", "Tron": "tron", "Zcash": "zcash",
        "Dogecoin": "dogecoin", "BitcoinCash": "bitcoin-cash", "Litecoin": "litecoin",
        "EthereumClassic": "ethereum-classic", "Cosmos": "cosmos", "Injective": "injective", "Dash": "dash",
    }
    rows = []
    for match in re.finditer(r'at\(\s*Coin::(\w+),\s*"([^"]+)",\s*"([^"]+)",', body):
        rows.append((coin_ids[match.group(1)], "", match.group(2), match.group(3)))
    for match in re.finditer(r'coin: Coin::(\w+),\s*passphrase: "([^"]*)",\s*path: "([^"]+)",\s*address: "([^"]+)"', body):
        rows.append((coin_ids[match.group(1)], match.group(2), match.group(3), match.group(4)))
    return rows


ABANDON = ("abandon " * 11 + "about").strip()


def check_wallet_addresses():
    rows = wallet_address_table()
    check("addresses.table-size", len(rows) == 43, str(len(rows)))
    seeds = {}
    for coin, passphrase, path, address in rows:
        seed = seeds.setdefault(passphrase, bip39_seed(ABANDON, passphrase))
        key, _ = derive(seed, path)
        mine = address_for(coin, path, key, legacy=address.startswith("1"))
        check(f"addresses.{coin}.{path}{'.TREZOR' if passphrase else ''}", mine == address, mine if mine != address else "")


def rust_literal(text):
    """The bytes of a Rust string or byte-string literal body, with line continuations removed."""
    return re.sub(r"\\\n\s*", "", text).encode()


def check_digest_known_answers():
    """Every DigestCase of the self-checks recomputed with Python's hashlib/hmac or the Keccak here."""
    functions = {
        "SHA-256": lambda key, m: hashlib.sha256(m).digest(),
        "SHA-512": lambda key, m: hashlib.sha512(m).digest(),
        "RIPEMD-160": lambda key, m: ripemd160(m),
        "BLAKE2b-256": lambda key, m: hashlib.blake2b(m, digest_size=32).digest(),
        "HMAC-SHA-256": lambda key, m: hmac.new(key, m, hashlib.sha256).digest(),
        "HMAC-SHA-512": lambda key, m: hmac.new(key, m, hashlib.sha512).digest(),
        "Keccak-256": lambda key, m: keccak256(m),
    }
    pattern = re.compile(
        r'DigestCase \{\s*algorithm: "([^"]+)",\s*function: \w+,\s*key: (b"(?:[^"\\]|\\.)*"|&LONG_KEY),'
        r'\s*message: b"((?:[^"\\]|\\\n\s*|\\.)*)",\s*expected: "((?:[^"\\]|\\\n\s*)*)",'
    )
    count = 0
    for path in sorted((ROOT / "src").rglob("*.rs")):
        for algorithm, key, message, expected in pattern.findall(path.read_text()):
            if algorithm == "Nothing":
                continue
            key_bytes = bytes([0xAA]) * 131 if key == "&LONG_KEY" else rust_literal(key[2:-1])
            got = functions[algorithm](key_bytes, rust_literal(message)).hex()
            want = rust_literal(expected).decode()
            count += 1
            check(f"digests.{path.relative_to(ROOT)}.{algorithm}.{count}", got == want, "" if got == want else got)
    check("digests.count", count == 12, str(count))


# DIP-0017 and DIP-0018 published vectors (dashpay/dips, read 2026-10-07): "abandon" x11 "about",
# empty passphrase; private key, compressed public key, HASH160, mainnet and testnet addresses.
DIP17_VECTORS = [
    ("0'/0'/0", "6bca392f43453b7bc33a9532b69221ce74906a8815281637e0c9d0bee35361fe",
     "03de102ed1fc43cbdb16af02e294945ffaed8e0595d3072f4c592ae80816e6859e", "f7da0a2b5cbd4ff6bb2c4d89b67d2f3ffeec0525",
     "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs", "tdash1krma5z3ttj75la4m93xcndna9ullamq9y5fzq2j7"),
    ("0'/0'/1", "eef58ce73383f63d5062f281ed0c1e192693c170fbc0049662a73e48a1981523",
     "02269ff766fcd04184bc314f5385a04498df215ce1e7193cec9a607f69bc8954da", "a5ff0046217fd1c7d238e3e146cc5bfd90832a7e",
     "dash1kzjl7qzxy9lar37j8r37z3kvt07epqe20ckxfezw", "tdash1kzjl7qzxy9lar37j8r37z3kvt07epqe20cxp68nq"),
    ("0'/1'/0", "cc05b4389712a2e724566914c256217685d781503d7cc05af6642e60260830db",
     "0317a3ed70c141cffafe00fa8bf458cec119f6fc039a7ba9a6b7303dc65b27bed3", "6d92674fd64472a3dfcfc3ebcfed7382bf699d7b",
     "dash1kpkeye606ez89g7lelp7hnldwwpt76va0v3j6x28", "tdash1kpkeye606ez89g7lelp7hnldwwpt76va0vp4fcmf"),
]
DIP18_P2SH = ("43fa183cf3fb6e9e7dc62b692aeb4fc8d8045636", "dash1sppl5xpu70aka8nacc4kj2htflydspzkxch4cad6")


def check_dip17_dip18():
    """DIP-0017 derives the keys on the mainnet path m/9'/5'/17'/...; DIP-0018 encodes the same
    HASH160 values for mainnet and testnet (an encoding vector, not a testnet derivation)."""
    seed = bip39_seed(ABANDON, "")
    for tail, private, public, h160, mainnet, testnet in DIP17_VECTORS:
        key, _ = derive(seed, f"m/9'/5'/17'/{tail}")
        pub = compressed(point_mul(key))
        ok = key.to_bytes(32, "big").hex() == private and pub.hex() == public and hash160(pub).hex() == h160
        for hrp, address in (("dash", mainnet), ("tdash", testnet)):
            ok &= bech32_encode(hrp, convert_bits(b"\xb0" + hash160(pub), 8, 5), BECH32M_CONST) == address
        check(f"dip17.{tail}", ok)
    p2sh = bech32_encode("dash", convert_bits(b"\x80" + bytes.fromhex(DIP18_P2SH[0]), 8, 5), BECH32M_CONST)
    check("dip18.p2sh-type-0x80", p2sh == DIP18_P2SH[1])
    table = (ROOT / "src/wallet/known_answers.rs").read_text()
    check("dip17.mhfe-table-carries-published", all(v[4] in table for v in DIP17_VECTORS))


def main(arguments):
    sections = {
        "dip17": check_dip17_dip18,
        "digests": check_digest_known_answers,
        "bip39": check_wordlist_and_bip39,
        "bip32": check_bip32_vectors,
        "primitives": check_primitives,
        "vectors": check_published_vectors,
        "rounds-table": check_published_rounds_table,
        "reduced": check_reduced_cost_containers,
        "repair": check_repair_words,
        "check-word": check_check_word_and_eff,
        "wallet-check": check_wallet_check,
        "addresses": check_wallet_addresses,
    }
    only = None
    if arguments[:1] == ["--only"]:
        only = arguments[1].split(",")
    for name, section in sections.items():
        if only is None or name in only:
            section()
    print(f"{len(FAILURES)} failed" + (": " + ", ".join(FAILURES) if FAILURES else ""))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
