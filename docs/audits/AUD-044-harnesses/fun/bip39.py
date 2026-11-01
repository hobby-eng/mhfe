# AUD-044 fun probe helper: BIP39 encoding from the specification's word list, independent of mhfe.
import hashlib, sys
W = open('tests/spec/scripts/bip39-english.txt').read().split()
def phrase(ent):
    bits = int.from_bytes(ent, 'big')
    cs = len(ent) * 8 // 32
    h = hashlib.sha256(ent).digest()
    total = (bits << cs) | (h[0] >> (8 - cs))
    n = (len(ent) * 8 + cs) // 11
    return ' '.join(W[(total >> (11 * (n - 1 - i))) & 2047] for i in range(n))
if __name__ == '__main__':
    print(phrase(bytes.fromhex(sys.argv[1])))
