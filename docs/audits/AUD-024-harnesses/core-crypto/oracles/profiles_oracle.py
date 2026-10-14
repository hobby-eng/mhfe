"""Independent oracle for MHFE-REPAIR-1, MHFE-PASSWORD-CHECK-1 and MHFE-WALLET-CHECK-SEED-1,
written from mhfe_spec/README.md and vectors/profiles/README.md only. Public test data only."""
import glob, hashlib, json, os, re, sys, unicodedata

cargo_home = os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))
src = open(sorted(glob.glob(cargo_home + "/registry/src/*/bip39-3.0.0/src/language/english.rs"))[0]).read()
WORDS = re.findall(r'"([a-z]+)"', src)
assert len(WORDS) == 2048
assert hashlib.sha256(("\n".join(WORDS) + "\n").encode()).hexdigest() == "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
IDX = {w: i for i, w in enumerate(WORDS)}
ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("OK  " if cond else "BAD ") + name, detail)

# ---- GF(2^11), x^11 + x^2 + 1, alpha = x
POLY = (1 << 11) | (1 << 2) | 1
def gmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        b >>= 1
        a <<= 1
        if a & (1 << 11): a ^= POLY
    return r
def gpow(a, n):
    r = 1
    for _ in range(n): r = gmul(r, a)
    return r
def generator(k):
    g = [1]  # highest degree first
    for p in range(1, k + 1):
        root_ = gpow(2, p)
        nxt = g + [0]
        for i, c in enumerate(g):
            nxt[i + 1] ^= gmul(c, root_)
        g = nxt
    return g
SPEC_G = {2: [1, 6, 8], 4: [1, 30, 216, 960, 1024], 6: [1, 126, 1181, 1719, 2029, 1077, 1034],
          8: [1, 510, 1509, 1770, 1837, 850, 1339, 600, 680]}
for k, g in SPEC_G.items():
    check(f"g_{k} coefficients", generator(k) == g, generator(k))
def polymod(m, g):
    # m, g highest first; g monic
    r = list(m)
    for i in range(len(m) - len(g) + 1):
        c = r[i]
        if c:
            for j in range(1, len(g)):
                r[i + j] ^= gmul(c, g[j])
        r[i] = 0
    return r[-(len(g) - 1):]
def repair_words(container, k):
    d = [IDX[w] for w in container.split()]
    r = polymod(d + [0] * k, generator(k))
    return " ".join(WORDS[x] for x in r)
def ev(c, x):
    s = 0
    for coef in c: s = gmul(s, x) ^ coef
    return s

vec3 = "tests/fixtures/suite3-vectors/"
vec4 = "tests/fixtures/suite4-vectors/"
rows = [
    (json.load(open(vec3 + "zero-12.json"))["container"], ["labor extra", "shaft pupil patient jewel", "credit buzz orbit tired sail coffee", "appear include vicious move uphold tiger song satoshi"]),
    (json.load(open(vec4 + "same-length-nonzero-12.json"))["container"], ["motor renew", "pitch lonely onion erode", "toe rather ribbon run enforce notice", "tilt object execute change cube domain vehicle hour"]),
    (json.load(open(vec4 + "same-length-nonzero-21.json"))["container"], ["glove blossom", "share mask pave crystal", "slow issue fame census cabbage clarify", "potato enemy similar myself check gesture fortune shiver"]),
    (" ".join(["abandon"] * 23 + ["art"]), ["clever gravity", "letter wealth borrow cable", "clap try lift setup innocent gather", "mirror coffee census note proof zebra begin barrel"]),
]
for container, cards in rows:
    for k, card in zip([2, 4, 6, 8], cards):
        got = repair_words(container, k)
        cw = [IDX[w] for w in (container + " " + got).split()]
        check(f"repair k={k} {container.split()[0]}..", got == card and all(ev(cw, gpow(2, j)) == 0 for j in range(1, k + 1)), got)

# ---- MHFE-PASSWORD-CHECK-1
eff_path = "vendor/eff-large-wordlist/eff_large_wordlist.txt"
raw = open(eff_path, "rb").read()
check("EFF sha256", hashlib.sha256(raw).hexdigest() == "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e")
EFF = [line.split("\t")[1] for line in raw.decode().split("\n") if line]
assert len(EFF) == 7776
def dice(r): return sum((int(c) - 1) * 6 ** (4 - i) for i, c in enumerate(r))
for rolls, ci, pw in [("11111 11112 11113 11114 11115", 104, "abacus abdomen abdominal abide abiding aids"),
                      ("66666 66666 66666 66666 66666", 7739, "zoom zoom zoom zoom zoom yelling"),
                      ("35214 62431 15543 44126 21365", 4150, "jovial trailing chokehold pavilion cresting ninth"),
                      ("24255 61534 11111 66622 26522", 5527, "drop-down t-shirt abacus yo-yo felt-tip rubble")]:
    d = [dice(r) for r in rolls.split()]
    c = (1 * d[0] + 5 * d[1] + 7 * d[2] + 11 * d[3] + 13 * d[4]) % 7776
    check("check word " + rolls, c == ci and " ".join(EFF[x] for x in d + [c]) == pw, c)
print("EFF longest word", max(len(w) for w in EFF))

# ---- MHFE-WALLET-CHECK-SEED-1
def T(entropy, passphrase):
    # BIP39 mnemonic of entropy
    h = hashlib.sha256(entropy).digest()
    bits = int.from_bytes(entropy, "big") << 8 | h[0]
    words = [WORDS[(bits >> (11 * (23 - i))) & 2047] for i in range(24)]
    m = " ".join(words)
    seed = hashlib.pbkdf2_hmac("sha512", unicodedata.normalize("NFKD", m).encode(), b"mnemonic" + unicodedata.normalize("NFKD", passphrase).encode(), 2048)
    return m, hashlib.sha256(b"MHFE-WALLET-CHECK-SEED-1" + (256).to_bytes(4, "big") + seed).hexdigest()
e1 = bytes(24) + (76562).to_bytes(8, "big")
e2 = bytes(24) + (98918).to_bytes(8, "big")
check("wallet check TREZOR", T(e1, "TREZOR")[1] == "0000e86481bdfe6dbf45e6e41fba4f309fcf09d3f0af2fe3f46736c663840853")
m2, t2 = T(e2, "")
check("wallet check empty", t2 == "0000ede77b44fbd62025e1d36a45ebe3846cf48f7b3e76ca6a91495fdadc1fb2" and m2.endswith("absorb another spoil"))
check("wallet check fail cases", T(e1, "")[1].startswith("ebd07f71") and T(e2, "TREZOR")[1].startswith("8d2b97fb"))
print("TREZOR phrase", T(e1, "TREZOR")[0])
sys.exit(0 if ok else 1)
