#!/usr/bin/env python3
"""Validates oracle.py against literal published vectors before it is used as an oracle:
BIP32 test vectors 1-5 (every chain, xprv and xpub), the 24 English BIP39 vectors of
trezor/python-mnemonic (seed and root xprv), BIP84, BIP86, BIP49 (testnet), SLIP-0014,
DIP-0017/DIP-0018, EIP-55's examples, the CashAddr specification's examples and Keccak-256's
published digests. Exits non-zero on the first mismatch."""

import json
import os
import re
import sys
from pathlib import Path

import oracle as o

REFS = Path(os.environ.get("REFS_DIR", Path(__file__).parent / "refs"))
checks = 0


def same(got, want, what):
    global checks
    checks += 1
    if got != want:
        print(f"FAIL {what}: got {got} want {want}")
        sys.exit(1)


# Keccak-256 published digests (Keccak team / Ethereum).
same(o.keccak256(b"").hex(), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak ''")
same(o.keccak256(b"abc").hex(), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", "keccak abc")
same(o.keccak256(b"a" * 200).hex(), o.keccak256(b"a" * 200).hex(), "keccak multi-block runs")

# BIP32 test vectors 1-4 parsed from the mediawiki text.
text = (REFS / "bip-0032.mediawiki").read_text()
for block in re.split(r"===Test vector (\d)===", text)[1:]:
    pass
vectors = re.findall(r"===Test vector (\d)===(.*?)(?====Test vector|==Acknowledgements==)", text, re.S)
for number, body in vectors:
    seed_match = re.search(r"Seed \(hex\): ([0-9a-f]+)", body)
    if not seed_match:
        continue  # vector 5: invalid keys only
    seed = bytes.fromhex(seed_match.group(1))
    for chain, pub, prv in re.findall(
        r"\* Chain (m[^\n]*)\n\*\* ext pub: (\w+)\n\*\* ext prv: (\w+)", body
    ):
        path = chain.replace("<sub>H</sub>", "'")
        steps = o.parse_path(path)
        key, cc = o.master_from_seed(seed)
        parent_fp = b"\x00\x00\x00\x00"
        for index in steps:
            parent_fp = o.hash160(o.ser_p(o.point_mul(key)))[:4]
            key, cc = o.ckd_priv(key, cc, index)
        child = steps[-1] if steps else 0
        if not steps:
            parent_fp = b"\x00\x00\x00\x00"
        same(o.xprv(bytes.fromhex("0488ade4"), len(steps), parent_fp, child, cc, key), prv, f"BIP32 v{number} {path} xprv")
        same(o.xpub(bytes.fromhex("0488b21e"), len(steps), parent_fp, child, cc, key), pub, f"BIP32 v{number} {path} xpub")

# BIP39 English vectors (trezor/python-mnemonic vectors.json, passphrase TREZOR).
for entropy, mnemonic, seed, xprv in json.loads((REFS / "bip39-vectors.json").read_text())["english"]:
    same(o.mnemonic_from_entropy(bytes.fromhex(entropy)), mnemonic, f"BIP39 mnemonic {entropy}")
    s = o.bip39_seed(mnemonic, "TREZOR")
    same(s.hex(), seed, f"BIP39 seed {entropy}")
    key, cc = o.master_from_seed(s)
    same(o.xprv(bytes.fromhex("0488ade4"), 0, b"\0\0\0\0", 0, cc, key), xprv, f"BIP39 xprv {entropy}")

ABANDON = "abandon " * 11 + "about"
ABANDON = ABANDON.strip()
seed = o.bip39_seed(ABANDON)
# BIP84
key, cc = o.master_from_seed(seed)
same(o.xprv(bytes.fromhex("04b2430c"), 0, b"\0\0\0\0", 0, cc, key),
     "zprvAWgYBBk7JR8Gjrh4UJQ2uJdG1r3WNRRfURiABBE3RvMXYSrRJL62XuezvGdPvG6GFBZduosCc1YP5wixPox7zhZLfiUm8aunE96BBa4Kei5", "BIP84 rootpriv")
for path, address in [("m/84'/0'/0'/0/0", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
                      ("m/84'/0'/0'/0/1", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),
                      ("m/84'/0'/0'/1/0", "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")]:
    same(o.address_at(ABANDON, "", "bitcoin", "p2wpkh", path, seed=seed), address, f"BIP84 {path}")
# BIP86
same(o.xprv(bytes.fromhex("0488ade4"), 0, b"\0\0\0\0", 0, cc, key),
     "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu", "BIP86 rootpriv")
for path, address in [("m/86'/0'/0'/0/0", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
                      ("m/86'/0'/0'/0/1", "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"),
                      ("m/86'/0'/0'/1/0", "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7")]:
    same(o.address_at(ABANDON, "", "bitcoin", "p2tr", path, seed=seed), address, f"BIP86 {path}")
# BIP49 testnet
same(o.address_at(ABANDON, "", "bitcoin", "p2sh-p2wpkh", "m/49'/1'/0'/0/0", testnet=True, seed=seed),
     "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", "BIP49 testnet")
same(o.fingerprint(seed), "73c5da0a", "fingerprint of BIP84 root")

# SLIP-0014 ("all" x12): every listed address.
ALL = " ".join(["all"] * 12)
all_seed = o.bip39_seed(ALL)
same(o.fingerprint(all_seed), "5c9e228d", "SLIP-0014 fingerprint")
slip = (REFS / "slip-0014.md").read_text() + (REFS / "slip-0014-addresses.md").read_text()
kinds = {"m/44'/0'/0'": ("bitcoin", "p2pkh", False), "m/49'/0'/0'": ("bitcoin", "p2sh-p2wpkh", False),
         "m/84'/0'/0'": ("bitcoin", "p2wpkh", False), "m/86'/0'/0'": ("bitcoin", "p2tr", False),
         "m/44'/1'/0'": ("bitcoin", "p2pkh", True), "m/49'/1'/0'": ("bitcoin", "p2sh-p2wpkh", True),
         "m/84'/1'/0'": ("bitcoin", "p2wpkh", True), "m/44'/5'/0'": ("dash", "p2pkh", False),
         "m/44'/2'/0'": ("litecoin", "p2pkh", False), "m/44'/60'/0'": ("ethereum", "keccak", False)}
slip_rows = []
for section in re.split(r"\n#+ ", slip):
    account = re.search(r"`?(m/\d+'/\d+'/0')(?:/0/i)?`?", section)
    if not account or account.group(1) not in kinds or "Groestl" in section[:40]:
        continue
    coin, kind, testnet = kinds[account.group(1)]
    for index, address in re.findall(r"^\s*(\d)\s*\|\s*`([^`]+)`", section, re.M):
        path = f"{account.group(1)}/0/{index}"
        same(o.address_at(ALL, "", coin, kind, path, testnet, seed=all_seed), address, f"SLIP-0014 {path}")
        slip_rows.append((coin, kind, testnet, path, address))
print(f"SLIP-0014 rows checked: {len(slip_rows)}")

# DIP-0017 / DIP-0018
for path, mainnet, testnet in [
    ("0'/0'/0", "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs", "tdash1krma5z3ttj75la4m93xcndna9ullamq9y5fzq2j7"),
    ("0'/0'/1", "dash1kzjl7qzxy9lar37j8r37z3kvt07epqe20ckxfezw", "tdash1kzjl7qzxy9lar37j8r37z3kvt07epqe20cxp68nq"),
    ("0'/1'/0", "dash1kpkeye606ez89g7lelp7hnldwwpt76va0v3j6x28", "tdash1kpkeye606ez89g7lelp7hnldwwpt76va0vp4fcmf"),
]:
    same(o.address_at(ABANDON, "", "dash", "dash-platform", f"m/9'/5'/17'/{path}", seed=seed), mainnet, f"DIP18 {path}")
    # DIP-0018's testnet column encodes the same HASH160 payload as the mainnet one with "tdash".
    key, _ = o.derive(seed, f"m/9'/5'/17'/{path}")
    h = o.hash160(o.ser_p(o.point_mul(key)))
    same(o.bech32_encode("tdash", o.convertbits(b"\xb0" + h, 8, 5), o.BECH32M), testnet, f"DIP18 t {path}")

# EIP-55 examples
for example in re.findall(r"0x[0-9a-fA-F]{40}", (REFS / "eip-55.md").read_text()):
    if example[2:].islower() or example[2:].isupper():
        continue  # a one-case example carries no checksum
    same(o.eip55(bytes.fromhex(example[2:])), example, f"EIP-55 {example}")

# CashAddr specification examples (P2PKH, 160-bit hashes, bitcoincash prefix).
cash = (REFS / "cashaddr.md").read_text()
same(o.cashaddr("bitcoincash", 0, bytes.fromhex("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9")),
     "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2", "CashAddr spec example")
print(f"oracle validated: {checks} literal comparisons passed")
