"""Independent, cheap replay of the public seed-check fixture; no MHFE or Argon2 evaluation."""

import hashlib
import json
from pathlib import Path
import re
import sys

words = re.findall(r'"([a-z]+)"', Path(sys.argv[1]).read_text())
assert len(words) == 2048
# The implementation's public test fixture: 24 zero bytes and a big-endian counter of 76,562.
entropy = bytes(24) + (76_562).to_bytes(8, "big")
encoded = (int.from_bytes(entropy, "big") << 8) | hashlib.sha256(entropy).digest()[0]
phrase = " ".join(words[(encoded >> (11 * (23 - i))) & 2047] for i in range(24))
seed = hashlib.pbkdf2_hmac("sha512", phrase.encode(), b"mnemonicTREZOR", 2048, 64)
domain = b"MHFE-WALLET-CHECK-SEED-1"
implemented = hashlib.sha256(domain + (256).to_bytes(4, "big") + seed).hexdigest()
documented = hashlib.sha256(domain + seed).hexdigest()
assert implemented == "0000e86481bdfe6dbf45e6e41fba4f309fcf09d3f0af2fe3f46736c663840853"
assert not documented.startswith("0000")
print(json.dumps({
    "fixture": "public wallet_check::TREZOR_COUNTER = 76562",
    "implementedDigest": implemented,
    "supplementDigestWithoutENT": documented,
    "byteContractMismatchReproduced": True,
}))
