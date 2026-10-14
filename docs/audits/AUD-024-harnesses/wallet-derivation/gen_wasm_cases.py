#!/usr/bin/env python3
"""Cases for the browser package's wallet bindings that run without Argon2: walletFingerprint,
describeAddress, searchCandidates and searchDecoy (the container's own wallet), with expected
values from oracle.py only."""
import hashlib, json, os
from pathlib import Path
import oracle as o

HERE = Path(os.environ.get("OUT_DIR", Path(__file__).parent))
cases = []
def ent(label, size): return hashlib.sha256(label.encode()).digest()[:size]
container = o.mnemonic_from_entropy(ent("aud024 wasm container", 32))
words = container.split()
written = " ".join(words[:-1] + ["?"])
seed = o.bip39_seed(container, "")
types = [("bitcoin","p2pkh","44'/0'",False),("bitcoin","p2sh-p2wpkh","49'/0'",False),("bitcoin","p2wpkh","84'/0'",False),
         ("bitcoin","p2tr","86'/0'",False),("bitcoin","p2wpkh","84'/1'",True),("bitcoin","p2tr","86'/1'",True),
         ("litecoin","p2pkh","44'/2'",False),("litecoin","p2sh-p2wpkh","49'/2'",False),("litecoin","p2wpkh","84'/2'",False),
         ("dogecoin","p2pkh","44'/3'",False),("dash","p2pkh","44'/5'",False),("zcash","p2pkh","44'/133'",False),
         ("bitcoin-cash","p2pkh","44'/145'",False),("xrp","p2pkh","44'/144'",False),("cosmos","p2pkh","44'/118'",False),
         ("ethereum","keccak","44'/60'",False),("ethereum-classic","keccak","44'/61'",False),("tron","keccak","44'/195'",False),
         ("injective","keccak","44'/60'",False),("dash","dash-platform","9'/5'/17'",False),("dash","dash-platform","9'/1'/17'",True)]
for coin, kind, root, testnet in types:
    chain = "1'" if kind == "dash-platform" else "1"
    for path, search in [(f"m/{root}/2'/{chain}/9", ""), (f"m/{root}/2147483647'/{chain}/2147483647", None)]:
        address = o.address_at(container, "", coin, kind, path, testnet, seed=seed)
        cases.append({"t": "decoy", "id": f"wasm decoy {coin} {kind} {path} at path", "written": written,
                      "kind": "address", "reference": address, "coin": coin, "path": path, "pass": "", "gap": 20,
                      "container": container, "found_path": path})
        if search is not None:
            cases.append({"t": "decoy", "id": f"wasm decoy {coin} {kind} {path} searched", "written": written,
                          "kind": "address", "reference": address, "coin": coin, "path": "", "pass": "", "gap": 20,
                          "container": container, "found_path": path})
for i, size in enumerate([16, 20, 24, 28, 32]):
    phrase = o.mnemonic_from_entropy(ent(f"aud024 wasm phrase {i}", size))
    for passphrase in ["", "TREZOR", "Café ﬁ ＰÅ① \U0001f510 й", "ﷺ"]:
        cases.append({"t": "fp", "id": f"wasm fingerprint {size * 8} bits {passphrase[:6]!r}", "phrase": phrase,
                      "pass": passphrase, "fp": o.fingerprint(o.bip39_seed(phrase, passphrase))})
cases.append({"t": "decoy", "id": "wasm decoy fingerprint", "written": written, "kind": "fingerprint",
              "reference": o.fingerprint(seed), "coin": "", "path": "", "pass": "", "gap": 20, "container": container})
cases.append({"t": "scope", "id": "wasm describeAddress default", "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
              "coin": "bitcoin", "path": "", "gap": 0, "search": "m/84'/0'/0'-9'/0-1/0-99", "addresses": 2000})
# Findings, stated as the behaviour the cited rules require (expected to fail at b6fca69).
deep = "m/" + "/".join(["0"] * 256)
cases.append({"t": "refused", "finding": True, "id": "wasm describeAddress refuses a path of depth 256",
              "call": "describeAddress", "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "coin": "bitcoin",
              "path": deep, "code": "INVALID_DERIVATION_PATH"})
cases.append({"t": "message", "finding": True, "id": "wasm searchCandidates names the word count of 23 words with ?",
              "written": " ".join(words[:-2] + ["?"]), "not_contains": "marked missing"})
(HERE / "wasm-cases.json").write_text(json.dumps(cases, ensure_ascii=False))
print(len(cases), "wasm cases")
