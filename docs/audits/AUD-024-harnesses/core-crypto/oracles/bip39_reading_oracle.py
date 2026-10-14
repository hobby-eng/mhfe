"""BIP39 encoding and the specification's "Reading words" rule, written from BIP-0039 and
mhfe_spec/README.md, against the Rust probe (read_phrase and phrase_from_entropy). Deterministic
public inputs only. Usage: bip39_reading_oracle.py <probe binary>"""
import glob, os, hashlib, random, re, subprocess, sys

cargo_home = os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))
src = open(sorted(glob.glob(cargo_home + "/registry/src/*/bip39-3.0.0/src/language/english.rs"))[0]).read()
W = re.findall(r'"([a-z]+)"', src); IDX = {w: i for i, w in enumerate(W)}
probe = sys.argv[1]
rng = random.Random(20261014)

def phrase(e):
    cs = len(e) * 8 // 32
    bits = int.from_bytes(e, "big") << cs | hashlib.sha256(e).digest()[0] >> (8 - cs)
    n = (len(e) * 8 + cs) // 11
    return [W[(bits >> (11 * (n - 1 - i))) & 2047] for i in range(n)]

def resolve(token):
    """The specification's rule for one input word, letter case ignored (ASCII)."""
    t = token.lower() if token.isascii() else token  # only ASCII letters change case
    if t in IDX: return t
    if len(t) >= 4:
        c = [w for w in W if w.startswith(t)]
        if len(c) == 1: return c[0]
    return None

def expected(text):
    toks = text.split()  # Python str.split() splits on Unicode whitespace as Rust split_whitespace
    if len(toks) not in (12, 15, 18, 21, 24): return "err INVALID_PHRASE"
    words = [resolve(t) for t in toks]
    if None in words: return "err INVALID_PHRASE"
    n = len(words); bits = 0
    for w in words: bits = bits << 11 | IDX[w]
    cs = n // 3; e = (bits >> cs).to_bytes(n * 4 // 3, "big")
    if hashlib.sha256(e).digest()[0] >> (8 - cs) != bits & ((1 << cs) - 1): return "err INVALID_PHRASE"
    return "ok " + " ".join(words)

# 1. Encoding: every entropy width, edge patterns and random entropies.
entropies = []
for size in (16, 20, 24, 28, 32):
    for fill in (0x00, 0xff, 0x7f, 0x80, 0x01):
        entropies.append(bytes([fill]) * size)
    entropies += [bytes(rng.randrange(256) for _ in range(size)) for _ in range(200)]
entropies += [bytes(15), bytes(17), bytes(33), b""]  # widths BIP39 does not have
out = subprocess.run([probe, "phrases-of-entropy"], input="\n".join(e.hex() for e in entropies) + "\n",
                     capture_output=True, text=True, check=True).stdout.splitlines()
bad = 0
for e, got in zip(entropies, out):
    want = ("ok " + " ".join(phrase(e))) if len(e) in (16, 20, 24, 28, 32) else "err INTERNAL_ERROR"
    if got != want:
        bad += 1; print("ENCODING DIFF", e.hex(), got, want)
print(f"encoding: {len(entropies)} entropies, {bad} differences")

# 2. Reading: every word of the list as first word, typed in several ways.
cases = []
for i, w in enumerate(W):
    size = rng.choice((16, 20, 24, 28, 32))
    e = bytearray(rng.randrange(256) for _ in range(size))
    v = int.from_bytes(e, "big") & ~(2047 << (size * 8 - 11)) | i << (size * 8 - 11)
    words = phrase(v.to_bytes(size, "big"))
    typed = [x[:4] if len(x) > 4 and rng.random() < 0.5 else x for x in words]
    typed = [x.upper() if rng.random() < 0.3 else x for x in typed]
    sep = rng.choice([" ", "  ", "\t", " ", "　", " \n "])
    cases.append(sep.join(typed) + rng.choice(["", " ", "\n"]))
# Negative and boundary cases.
base = phrase(bytes(16))
cases += [
    " ".join(base[:11] + ["aba"]),                 # three letters that are no word
    " ".join(["act"] + base[1:]),                  # a three-letter word that begins others (checksum may fail)
    " ".join(base[:11] + ["abou"]),                # four letters
    " ".join(base[:11] + ["aboutx"]),              # longer than the word
    " ".join(base[:11] + ["Kite"]),           # Kelvin sign
    " ".join(base[:11] + ["abo​ut"]),         # zero-width space inside a word
    " ".join(base[:11] + ["ａｂｏｕｔ"]),          # full-width letters
    " ".join(base),                                # valid
    " ".join(base[:11]),                           # 11 words
    " ".join(base + ["abandon"]),                  # 13 words
    " ".join(["abandon"] * 12),                    # bad checksum
]
out = subprocess.run([probe, "read-phrases"], input="\n".join(c.encode().hex() for c in cases) + "\n",
                     capture_output=True, text=True, check=True).stdout.splitlines()
bad = 0
for c, got in zip(cases, out):
    want = expected(c)
    if got != want:
        bad += 1; print("READING DIFF", repr(c), got, want)
print(f"reading: {len(cases)} typed phrases, {bad} differences")
sys.exit(1 if bad else 0)
