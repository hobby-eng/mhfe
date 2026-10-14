"""Independent suite 3 and suite 4 encryption written from mhfe_spec/README.md, with Argon2id from
OpenSSL (cryptography) at the reduced test cost of src/test_support.rs (256 KiB, 1 pass, 4 lanes),
to check the Rust reduced-cost containers of src/mhfe.rs. Public test data only."""
import glob, os, hashlib, hmac, re, sys
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

cargo_home = os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))
src = open(sorted(glob.glob(cargo_home + "/registry/src/*/bip39-3.0.0/src/language/english.rs"))[0]).read()
W = re.findall(r'"([a-z]+)"', src); IDX = {w: i for i, w in enumerate(W)}

def to_entropy(phrase):
    ws = phrase.split(); n = len(ws); bits = 0
    for w in ws: bits = bits << 11 | IDX[w]
    cs = n // 3; ent = bits >> cs
    e = ent.to_bytes((n // 3) * 4, "big")
    assert hashlib.sha256(e).digest()[0] >> (8 - cs) == bits & ((1 << cs) - 1)
    return e
def to_phrase(e):
    cs = len(e) * 8 // 32; bits = int.from_bytes(e, "big") << cs | hashlib.sha256(e).digest()[0] >> (8 - cs)
    n = (len(e) * 8 + cs) // 11
    return " ".join(W[(bits >> (11 * (n - 1 - i))) & 2047] for i in range(n))
def be32(v): return v.to_bytes(4, "big")
def perm(x, pw, suite, mem=0, pim=0, cost=(256, 1)):
    if suite == 3:
        sid = b"MHFE-BIP39-256-EXPERIMENTAL-3"; extra = b""
    else:
        sid = b"MHFE-BIP39-LP-EXPERIMENTAL-4"; extra = be32(len(x) * 8)
    h = len(x) // 2; L, R = x[:h], x[h:]
    for i in range(12):
        msg = be32(mem) + be32(pim) + extra + be32(i) + R
        salt = hashlib.blake2b(sid + b"/ROUND-SALT" + msg, digest_size=32).digest()[:16]
        k = Argon2id(salt=salt, length=32, iterations=cost[1], lanes=4, memory_cost=cost[0]).derive(pw)
        m = hmac.new(k, sid + b"/ROUND-MASK" + msg, hashlib.sha256).digest()[:h]
        L, R = R, bytes(a ^ b for a, b in zip(L, m))
    return L + R
ZERO_12 = "abandon " * 11 + "about"
e = to_entropy(ZERO_12)
x3 = e + hashlib.sha256(e).digest()[: 32 - len(e)]
c3 = to_phrase(perm(x3, b"public test password", 3))
c4 = to_phrase(perm(e, b"public test password", 4))
want3 = "slush crime nose carry menu cabbage already cart lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope dream sweet"
want4 = "program adjust rain raven flip eternal spider bulb under soup enrich ensure"
print("suite 3", "OK" if c3 == want3 else "BAD", c3)
print("suite 4", "OK" if c4 == want4 else "BAD", c4)
sys.exit(0 if (c3 == want3 and c4 == want4) else 1)
