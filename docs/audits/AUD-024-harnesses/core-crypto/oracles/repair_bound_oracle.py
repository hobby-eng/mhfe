"""Property test of the MHFE-REPAIR-1 decoder through the Rust probe, with an independent GF(2^11)
written from mhfe_spec/README.md: within the bound 2e + s <= k the original container must come
back; beyond it the result must be refused or be a checksum-valid container that, with the
received card, is a codeword within the bound of what was received. Deterministic public data."""
import glob, os, hashlib, random, re, subprocess, sys
cargo_home = os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))
src = open(sorted(glob.glob(cargo_home + "/registry/src/*/bip39-3.0.0/src/language/english.rs"))[0]).read()
W = re.findall(r'"([a-z]+)"', src); IDX = {w: i for i, w in enumerate(W)}
POLY = 0x805
def gmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        b >>= 1; a <<= 1
        if a & 0x800: a ^= POLY
    return r
def gpow(a, n):
    r = 1
    for _ in range(n): r = gmul(r, a)
    return r
def gen(k):
    g = [1]
    for p in range(1, k + 1):
        rt = gpow(2, p); nx = g + [0]
        for i, c in enumerate(g): nx[i + 1] ^= gmul(c, rt)
        g = nx
    return g
def parity(d, k):
    r = list(d) + [0] * k; g = gen(k)
    for i in range(len(d)):
        c = r[i]
        if c:
            for j in range(1, k + 1): r[i + j] ^= gmul(c, g[j])
    return r[len(d):]
def ev(c, x):
    s = 0
    for v in c: s = gmul(s, x) ^ v
    return s
def phrase(e):
    cs = len(e) * 8 // 32
    bits = int.from_bytes(e, "big") << cs | hashlib.sha256(e).digest()[0] >> (8 - cs)
    n = (len(e) * 8 + cs) // 11
    return [(bits >> (11 * (n - 1 - i))) & 2047 for i in range(n)]
def valid(nums):
    n = len(nums); bits = 0
    for v in nums: bits = bits << 11 | v
    cs = n // 3; e = (bits >> cs).to_bytes(n * 4 // 3, "big")
    return hashlib.sha256(e).digest()[0] >> (8 - cs) == bits & ((1 << cs) - 1)

rng = random.Random(24024)
cases = []
for _ in range(4000):
    n = rng.choice((12, 15, 18, 21, 24)); k = rng.choice((2, 4, 6, 8))
    data = phrase(bytes(rng.randrange(256) for _ in range(n * 4 // 3)))
    card = parity(data, k); cw = data + card
    within = rng.random() < 0.6
    if within:
        s = rng.randrange(k + 1); e = rng.randrange((k - s) // 2 + 1)
    else:
        s = rng.randrange(k + 2); e = rng.randrange(1, k // 2 + 3)
        if 2 * e + s <= k: e = (k - s) // 2 + 1
    pos = rng.sample(range(n + k), min(s + e, n + k))
    recv = list(cw); unread = set(pos[:s])
    for p in pos[s:]: recv[p] = (recv[p] + 1 + rng.randrange(2047)) % 2048
    toks = ["?" if i in unread else W[v] for i, v in enumerate(recv)]
    cases.append((n, k, within, cw, recv, unread, " ".join(toks[:n]) + "\t" + " ".join(toks[n:])))
out = subprocess.run([sys.argv[1], "repair"], input="\n".join(c[-1] for c in cases) + "\n",
                     capture_output=True, text=True, check=True).stdout.splitlines()
assert len(out) == len(cases)
bad = within_ok = beyond_refused = beyond_given = 0
for (n, k, within, cw, recv, unread, _), got in zip(cases, out):
    if within:
        if got == "ok " + " ".join(W[v] for v in cw[:n]): within_ok += 1
        else: bad += 1; print("WITHIN BOUND NOT REPAIRED", n, k, got)
        continue
    if got.startswith("err"):
        beyond_refused += 1; continue
    beyond_given += 1
    data = [IDX[w] for w in got[3:].split()]
    # The decoder's codeword: its data and the parity it implies; it must stay within the bound.
    full = data + parity(data, k)
    s = len(unread); e = sum(1 for i in range(n + k) if i not in unread and full[i] != recv[i])
    if not valid(data) or 2 * e + s > k:
        bad += 1; print("BEYOND BOUND WRONG", n, k, got, s, e)
print(f"within bound: {within_ok} repaired; beyond: {beyond_refused} refused, {beyond_given} given as another valid container within the bound; {bad} violations")
sys.exit(1 if bad else 0)
