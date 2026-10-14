"""Independent check (no mhfe code): BIP39 checksum and BIP32 master key fingerprint of the
colliding candidates the harness reported, plus the expected number of colliding pairs."""
import hashlib, hmac, re, sys

src = open(sys.argv[1]).read()
WORDS = re.findall(r'"([a-z]+)"', src)
assert len(WORDS) == 2048
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b:
        l = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)

def mul(k, pt):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r

def checksum_ok(words):
    bits = ''.join(format(WORDS.index(w), '011b') for w in words)
    cs = len(bits) // 33
    ent = int(bits[:-cs], 2).to_bytes((len(bits) - cs) // 8, 'big')
    return format(hashlib.sha256(ent).digest()[0], '08b')[:cs] == bits[-cs:]

def fingerprint(phrase, passphrase=""):
    seed = hashlib.pbkdf2_hmac('sha512', phrase.encode(), ("mnemonic" + passphrase).encode(), 2048)
    key = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[:32]
    x, y = mul(int.from_bytes(key, 'big'), G)
    pub = bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')
    return hashlib.new('ripemd160', hashlib.sha256(pub).digest()).hexdigest()[:8]

prefix = ["abandon"] * 10
pairs = [("amused buzz", "employ giraffe"), ("able ghost", "best student")]
for a, b in pairs:
    for last in (a, b):
        words = prefix + last.split()
        print(f"abandon x10 {last}: checksum {'valid' if checksum_ok(words) else 'INVALID'}, "
              f"fingerprint {fingerprint(' '.join(words))}")
n = 2048 * 2048 // 16
print(f"candidates: {n}; expected colliding pairs n(n-1)/2/2^32 = {n*(n-1)/2/2**32:.3f}")
p_other = 1 - (1 - 2**-32) ** (n - 1)
print(f"P(another candidate shares the owner's fingerprint) = {p_other:.3e} = 1 in {1/p_other:,.0f}")
print(f"P(that candidate comes first, so the search returns it) ~ {p_other/2:.3e} = 1 in {2/p_other:,.0f}")
n24 = 2048 * 2048 // 256
p24 = 1 - (1 - 2**-32) ** (n24 - 1)
print(f"24-word container: {n24} candidates, P(wrong) ~ 1 in {2/p24:,.0f}")
