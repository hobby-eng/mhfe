"""Independent Argon2id oracle (OpenSSL via cryptography) for the engine's known answers."""
import sys
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def tag(password, salt, mem, passes, lanes=4, length=32, secret=None, ad=None):
    kw = {}
    if secret is not None:
        kw["secret"] = secret
    if ad is not None:
        kw["ad"] = ad
    return Argon2id(salt=salt, length=length, iterations=passes, lanes=lanes, memory_cost=mem, **kw).derive(password).hex()

ok = True
def check(name, got, want):
    global ok
    good = got == want
    ok &= good
    print(("OK  " if good else "BAD ") + name, got)

P = b"public test password"; S = b"0123456789abcdef"
check("small 1 MiB/1", tag(P, S, 1024, 1), "e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2")
check("64 MiB/3", tag(P, S, 65536, 3), "a3931f5728b235c605c02522f3302a8e90d0509a0c3db63ab4d2fcf75f345b5b")
check("256 MiB/2", tag(P, S, 262144, 2), "4a4a094750f2c17fc6507d38825ec9eac65e10fb2de9e9bf5e801d2af53f1efe")
check("RFC 9106 5.3", tag(b"\x01"*32, b"\x02"*16, 32, 3, secret=b"\x03"*8, ad=b"\x04"*12),
      "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
sys.exit(0 if ok else 1)
