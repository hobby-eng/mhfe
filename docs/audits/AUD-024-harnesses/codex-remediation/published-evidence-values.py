"""
Independent public-vector seed checks and BIP32 fingerprints, without
Argon2.
"""
import hashlib
import hmac
import json
import unicodedata
from pathlib import Path
P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
G = (
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = (3 * x * x * pow(2 * y, -1, P) if a == b else (v - y) * pow(u - x, -1, P)) % P
    out = (slope * slope - x - u) % P
    return (out, (slope * (x - out) - y) % P)


def seed(phrase, passphrase):
    return hashlib.pbkdf2_hmac('sha512', unicodedata.normalize('NFKD', phrase).encode(),
        b'mnemonic' + unicodedata.normalize('NFKD', passphrase).encode(), 2048)


def fingerprint(phrase, passphrase):
    key = int.from_bytes(hmac.digest(b'Bitcoin seed', seed(phrase, passphrase), 'sha512')[:32],
        'big')
    out, point = (None, G)
    while key:
        if key & 1:
            out = add(out, point)
        point = add(point, point)
        key >>= 1
    x, y = out
    public = bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')
    return hashlib.new('ripemd160', hashlib.sha256(public).digest()).digest()[:4].hex()


folder = Path('tests/fixtures/suite3-vectors')
zero12 = json.loads((folder / 'zero-12.json').read_text())['inputs']['phrase']
assert fingerprint(zero12, '') == '73c5da0a'
for name in ['zero-24', 'ambiguous-12-21']:
    vector = json.loads((folder / (name + '.json')).read_text())
    reading = next((reading for reading in vector['recovery'] if reading['words'] == 24))['phrase']
    for passphrase in ['', 'TREZOR'] if name == 'zero-24' else ['']:
        digest = hashlib.sha256(b'MHFE-WALLET-CHECK-SEED-1' + 256 .to_bytes(4,
                'big') + seed(reading, passphrase)).digest()
        print(name, repr(passphrase), 'wallet-check:', digest.hex(), 'passes:',
            digest[:2] == b'\x00\x00')
    if name == 'zero-24':
        for passphrase in ['', 'TREZOR']:
            print(name, repr(passphrase), 'master fingerprint:',
                fingerprint(vector['inputs']['phrase'], passphrase))
