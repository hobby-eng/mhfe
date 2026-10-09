#!/usr/bin/env python3
"""Bind unchanged crypto inputs to AUD-016 without executing a vector or Argon2 call."""

import hashlib
from pathlib import Path


# SHA-256 values from AUD-016's retained closeout-mhfe-code-manifest.txt. These are
# byte-identity evidence for the reviewed files, not independent cryptographic results.
BASELINE = {
    "src/feistel.rs": "9eaaaedb82b318bc38cef059c648ac9ae7201a7d6cd50d280aad22d9673496b0",
    "src/packing.rs": "d36d8aa8e21fd4f751404806a2cbc07ea83db448681f94f2e7defd370fbf24be",
    "src/password.rs": "6c2b1bab6c6d4ae52ccc6479df7033785dca32f8bb6e23501dfa810d1dc51e45",
    "src/suite.rs": "dbd4b65fe2b7395b33a13264ab2a12b9c137cd113aa94e5fc257cceb6d82dcb3",
    "src/detection.rs": "e40a3581138b742da66f5296c029293eb9e571c7fa54370e34da872308c8d14a",
    "src/wallet_check.rs": "081ad4de554c943c61e8a2c7631c3cff21f737b24a1990a8c09e606990b82fc3",
    "src/engine/native.rs": "ee3627797674b948fbab390c91ae464ec79c0ca13566d0192030bd2cbf9c4599",
    "src/engine/ffi.rs": "e6fd2de0e4146b0931425de44830e4c82c1996acb9daa9aad9b2870bb6839947",
    "src/engine/browser.rs": "299f355a9904a2946bb52147d5f7ea9913354be1b7674c528adb0290e6fbabf1",
    "Cargo.toml": "c484ef408592209c77bd3e93f1a9def0291ddb394e317dd987f8aacc4db29c3a",
    "Cargo.lock": "c80fcc5f3bd5dfe967156dc4911980c6350975789ca84d36a1e09402e5efc60c",
    "vendor/phc-winner-argon2/src/argon2.c": "b1289ec7134e8502e9113396fdac89402bf2575ee1b35e33fb7410f2fb63bb6d",
}


def main():
    failures = 0
    for name, expected in BASELINE.items():
        actual = hashlib.sha256(Path(name).read_bytes()).hexdigest()
        passed = actual == expected
        failures += not passed
        print(f"{'PASS' if passed else 'FAIL'} {name} {actual}")
    print(f"{len(BASELINE)} identity checks, {failures} failures; no vectors executed")
    return int(failures != 0)


if __name__ == "__main__":
    raise SystemExit(main())
