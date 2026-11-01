#!/usr/bin/env python3
"""AUD-044 fun probe: BIP39 seeds and BIP32 master key fingerprints for every length, the edge
entropies and passphrases that NFKD changes, computed here with hashlib and unicodedata and compared
with the library's. Also the ways a phrase may be typed. Public test data only."""
import hashlib, hmac, os, random, subprocess, sys, unicodedata
sys.path.insert(0, '/nonexistent')
src = open('../tmp/aud044/fun/fingerprint_pairs.py').read().split("BASE='renew")[0]
exec(src)
PROBE = '../tmp/aud044/target/release/fun-probes'
W = open('tests/spec/scripts/bip39-english.txt').read().split()
def phrase(ent):
    bits = int.from_bytes(ent, 'big'); cs = len(ent) * 8 // 32
    total = (bits << cs) | (hashlib.sha256(ent).digest()[0] >> (8 - cs))
    n = (len(ent) * 8 + cs) // 11
    return ' '.join(W[(total >> (11 * (n - 1 - i))) & 2047] for i in range(n))
def fp(words, passphrase):
    seed = hashlib.pbkdf2_hmac('sha512', words.encode(), b'mnemonic' + unicodedata.normalize('NFKD', passphrase).encode(), 2048)
    I = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    p = mul(int.from_bytes(I[:32], 'big'))
    return ripemd160(hashlib.sha256(bytes([2 + (p[1] & 1)]) + p[0].to_bytes(32, 'big')).digest())[:4].hex()
random.seed(44)
passphrases = ['', 'TREZOR', 'パスワード', '㎡', 'Å', 'é', 'ﬁ x', ' leading and trailing ', 'a' * 300, '\U0001f510']
rows = []
for size in (16, 20, 24, 28, 32):
    entropies = [bytes(size), b'\xff' * size, bytes(size - 1) + b'\x01', b'\x7f' * size, b'\x80' * size, bytes(random.randrange(256) for _ in range(size))]
    for ent in entropies:
        for q in random.sample(passphrases, 3) + ['']:
            rows.append((phrase(ent), q))
lines = ''.join(f"{q.encode().hex() or '00'[:0]} {p}\n" if q else f" {p}\n" for p, q in rows)
out = subprocess.run([PROBE, 'fingerprints'], input=lines, capture_output=True, text=True).stdout.split('\n')
same = sum(1 for (p, q), o in zip(rows, out) if o == fp(p, q))
print(f"{len(rows)} phrase and passphrase pairs, {same} fingerprints the same")
for (p, q), o in zip(rows, out):
    if o != fp(p, q):
        print('DIFFERS', p[:40], repr(q), o, fp(p, q))
# Ways of typing one phrase.
base = 'legal winner thank year wave sausage worth useful legal winner thank yellow'
typed = {
    'capitals': base.upper(),
    'tabs and newlines inside a line': base.replace(' ', '\t \t'),
    'no-break spaces': base.replace(' ', ' '),
    'ideographic spaces': base.replace(' ', '　'),
    'four letters': ' '.join(w[:4] for w in base.split()),
    'five letters': ' '.join(w[:5] for w in base.split()),
    'three letters': ' '.join(w[:3] for w in base.split()),
    'zero-width space in a word': base.replace('legal', 'le​gal', 1),
    'full-width letters': base.replace('legal', 'ｌｅｇａｌ', 1),
    'a word with a letter too many': base.replace('legal', 'legals', 1),
    'a word with a Kelvin sign': base.replace('thank', 'thanK', 1),
}
good = fp(base, '')
lines = ''.join(f" {t}\n" for t in typed.values())
out = subprocess.run([PROBE, 'fingerprints'], input=lines, capture_output=True, text=True).stdout.split('\n')
for (label, _), o in zip(typed.items(), out):
    print(f"{label}: {'same wallet' if o == good else o}")
