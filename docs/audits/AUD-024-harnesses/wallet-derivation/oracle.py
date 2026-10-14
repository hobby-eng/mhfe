#!/usr/bin/env python3
"""Independent wallet oracle for audit AUD-024 (wallet-derivation role).

Written from the specifications only: secp256k1 affine arithmetic (SEC 2), BIP32 CKDpriv,
BIP39 seeds (hashlib PBKDF2), Keccak-256 (own sponge, FIPS 202 permutation with the original
Keccak padding), Bech32/Bech32m (BIP173/BIP350 reference algorithm), Base58Check, CashAddr and
EIP-55. hashlib (OpenSSL) supplies SHA-256, SHA-512, HMAC and RIPEMD-160 only. Nothing here
calls the mhfe crate or its Rust dependencies.
"""

import hashlib
import hmac
import os
import unicodedata

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
HARDENED = 1 << 31


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def point_mul(k, point=G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def ser_p(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def ser_uncompressed(point):
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def sha256(data):
    return hashlib.sha256(data).digest()


def hash160(data):
    return hashlib.new("ripemd160", sha256(data)).digest()


# ---- BIP39 / BIP32 ----

REFS_DIR = os.environ.get("REFS_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "refs"))
WORDS = open(os.path.join(REFS_DIR, "bip39-english.txt")).read().split()
assert len(WORDS) == 2048
assert hashlib.sha256(("\n".join(WORDS) + "\n").encode()).hexdigest() == (
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
)


def mnemonic_from_entropy(entropy):
    bits = len(entropy) * 8
    checksum = sha256(entropy)[0] >> (8 - bits // 32)
    value = (int.from_bytes(entropy, "big") << (bits // 32)) | checksum
    count = (bits + bits // 32) // 11
    return " ".join(WORDS[(value >> (11 * (count - 1 - i))) & 2047] for i in range(count))


def entropy_of(mnemonic):
    numbers = [WORDS.index(word) for word in mnemonic.split()]
    total = len(numbers) * 11
    value = 0
    for number in numbers:
        value = (value << 11) | number
    cs = total // 33
    entropy = (value >> cs).to_bytes((total - cs) // 8, "big")
    assert mnemonic_from_entropy(entropy) == mnemonic, "checksum"
    return entropy


def bip39_seed(mnemonic, passphrase=""):
    password = unicodedata.normalize("NFKD", mnemonic).encode()
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    return hashlib.pbkdf2_hmac("sha512", password, salt, 2048)


def master_from_seed(seed):
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    key = int.from_bytes(digest[:32], "big")
    assert 0 < key < N
    return key, digest[32:]


def ckd_priv(key, chain, index):
    if index >= HARDENED:
        data = b"\x00" + key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = ser_p(point_mul(key)) + index.to_bytes(4, "big")
    digest = hmac.new(chain, data, hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    child = (tweak + key) % N
    assert tweak < N and child != 0
    return child, digest[32:]


def parse_path(text):
    steps = text.split("/")
    assert steps[0] == "m"
    out = []
    for step in steps[1:]:
        hardened = step.endswith("'") or step.endswith("h")
        value = int(step.rstrip("'h"))
        out.append(value + HARDENED if hardened else value)
    return out


def derive(seed, path):
    key, chain = master_from_seed(seed)
    for index in parse_path(path) if isinstance(path, str) else path:
        key, chain = ckd_priv(key, chain, index)
    return key, chain


def fingerprint(seed):
    key, _ = master_from_seed(seed)
    return hash160(ser_p(point_mul(key)))[:4].hex()


# ---- Base58Check ----

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
RIPPLE = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def base58check(payload, alphabet=B58):
    data = payload + sha256(sha256(payload))[:4]
    value = int.from_bytes(data, "big")
    out = ""
    while value:
        value, rem = divmod(value, 58)
        out = alphabet[rem] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return alphabet[0] * pad + out


def xprv(version, depth, parent_fp, child, chain, key):
    return base58check(
        version + bytes([depth]) + parent_fp + child.to_bytes(4, "big") + chain + b"\x00"
        + key.to_bytes(32, "big")
    )


def xpub(version, depth, parent_fp, child, chain, key):
    return base58check(
        version + bytes([depth]) + parent_fp + child.to_bytes(4, "big") + chain
        + ser_p(point_mul(key))
    )


# ---- Bech32 / Bech32m (BIP173, BIP350) ----

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32, BECH32M = 1, 0x2BC830A3


def polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_encode(hrp, data, const):
    values = hrp_expand(hrp) + data
    mod = polymod(values + [0] * 6) ^ const
    checksum = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    return out


def segwit_address(hrp, version, program):
    const = BECH32 if version == 0 else BECH32M
    return bech32_encode(hrp, [version] + convertbits(program, 8, 5), const)


# ---- Keccak-256 (original padding 0x01) ----

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56],
       [27, 20, 39, 8, 14]]
M64 = (1 << 64) - 1


def rol(v, n):
    return ((v << n) | (v >> (64 - n))) & M64 if n else v


def keccak_f(a):
    for rc in RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = rol(a[x][y], ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)]
             for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    msg = bytearray(data) + b"\x01"
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            a[x][y] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        a = keccak_f(a)
    out = b""
    for i in range(4):
        out += a[i % 5][i // 5].to_bytes(8, "little")
    return out


def eip55(address20):
    lower = address20.hex()
    digest = keccak256(lower.encode()).hex()
    return "0x" + "".join(c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(lower))


# ---- CashAddr ----


def cashaddr_polymod(values):
    gens = [0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470]
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        for i in range(5):
            if (c0 >> i) & 1:
                c ^= gens[i]
    return c ^ 1


def cashaddr(prefix, version_byte, payload):
    data = convertbits(bytes([version_byte]) + payload, 8, 5)
    pre = [ord(x) & 31 for x in prefix] + [0]
    mod = cashaddr_polymod(pre + data + [0] * 8)
    checksum = [(mod >> 5 * (7 - i)) & 31 for i in range(8)]
    return prefix + ":" + "".join(CHARSET[d] for d in data + checksum)


# ---- addresses of a key ----


def taproot_output(key):
    point = point_mul(key)
    if point[1] & 1:
        point = (point[0], P - point[1])
        key = N - key
    x = point[0].to_bytes(32, "big")
    tag = sha256(b"TapTweak")
    tweak = int.from_bytes(sha256(tag + tag + x), "big")
    assert tweak < N
    q = point_add(point, point_mul(tweak))
    return q[0].to_bytes(32, "big")


def address_of(coin, kind, key, testnet=False):
    point = point_mul(key)
    pub = ser_p(point)
    h = hash160(pub)
    if kind == "p2pkh":
        prefix = {
            "bitcoin": b"\x6f" if testnet else b"\x00",
            "bitcoin-cash-legacy": b"\x00",
            "litecoin": b"\x30",
            "dogecoin": b"\x1e",
            "dash": b"\x4c",
            "zcash": b"\x1c\xb8",
        }
        if coin == "xrp":
            return base58check(b"\x00" + h, RIPPLE)
        if coin == "bitcoin-cash":
            return cashaddr("bitcoincash", 0, h)
        if coin == "cosmos":
            return bech32_encode("cosmos", convertbits(h, 8, 5), BECH32)
        return base58check(prefix[coin] + h)
    if kind == "p2sh-p2wpkh":
        script_hash = hash160(b"\x00\x14" + h)
        prefix = {"bitcoin": b"\xc4" if testnet else b"\x05", "litecoin": b"\x32"}[coin]
        return base58check(prefix + script_hash)
    if kind == "p2wpkh":
        hrp = {"bitcoin": "tb" if testnet else "bc", "litecoin": "ltc"}[coin]
        return segwit_address(hrp, 0, h)
    if kind == "p2tr":
        return segwit_address("tb" if testnet else "bc", 1, taproot_output(key))
    if kind == "keccak":
        k = keccak256(ser_uncompressed(point)[1:])[12:]
        if coin == "tron":
            return base58check(b"\x41" + k)
        if coin == "injective":
            return bech32_encode("inj", convertbits(k, 8, 5), BECH32)
        return eip55(k)
    if kind == "dash-platform":
        return bech32_encode("tdash" if testnet else "dash",
                             convertbits(b"\xb0" + h, 8, 5), BECH32M)
    raise ValueError(kind)


def address_at(mnemonic, passphrase, coin, kind, path, testnet=False, seed=None):
    seed = seed or bip39_seed(mnemonic, passphrase)
    key, _ = derive(seed, path)
    return address_of(coin, kind, key, testnet)
