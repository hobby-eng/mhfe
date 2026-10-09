#!/usr/bin/env python3
"""AUD-010 crypto-core: finds a public passphrase P for which the MHFE-WALLET-CHECK-SEED-1 digest of
the 12-word phrase "abandon x11 about" (the original of the published vector zero-12), computed the
way mhfe's wallet_check::phrase_passes computes it, with BE32(128), starts with 16 zero bits.

The profile is defined for 256-bit entropy only; mhfe's rehearsal compare() nevertheless evaluates
it on every reading of a 24-word container, the 12-word reading of zero-12 included. probe.py then
asks the library: phrase_passes(phrase, P) must be true (as compare() uses it) while
wallet_check::verify(phrase, P) refuses the 12-word phrase. Prints the passphrase found.

    python3 short_reading_wallet_check.py [--max N]
"""

import hashlib
import sys
import unicodedata
from multiprocessing import Pool

PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
TAG = b"MHFE-WALLET-CHECK-SEED-1"


def digest(passphrase, bits):
    seed = hashlib.pbkdf2_hmac(
        "sha512", PHRASE.encode(), ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode(), 2048, 64
    )
    return hashlib.sha256(TAG + bits.to_bytes(4, "big") + seed).digest()


def try_range(start):
    for counter in range(start, start + 4096):
        passphrase = f"aud010 public probe {counter}"
        if digest(passphrase, 128)[:2] == b"\0\0":
            return passphrase
    return None


def main(arguments):
    limit = int(arguments[1]) if arguments[:1] == ["--max"] else 1 << 21
    with Pool() as pool:
        for found in pool.imap(try_range, range(0, limit, 4096)):
            if found:
                pool.terminate()
                print(f"passphrase: {found}")
                print(f"digest with BE32(128): {digest(found, 128).hex()}")
                print(f"digest with BE32(256): {digest(found, 256).hex()}")
                return 0
    print("none found")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
