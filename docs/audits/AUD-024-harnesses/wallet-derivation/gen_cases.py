#!/usr/bin/env python3
"""Writes the cases of the AUD-024 wallet-derivation probe: conformance.json (every case states
the published or independently computed behaviour, expected to pass) and findings.json (cases
that state the behaviour a cited rule requires, expected to fail where the defect exists).

Expected values come only from published documents (refs/) or from oracle.py, which
validate_oracle.py first checks against 186 literal published values."""

import hashlib
import json
import os
import re
import sys
from pathlib import Path

import oracle as o

HERE = Path(os.environ.get("OUT_DIR", Path(__file__).parent))
REFS = Path(os.environ.get("REFS_DIR", Path(__file__).parent / "refs"))
MHFE = Path(os.environ.get("MHFE_ROOT", "."))
ABANDON = " ".join(["abandon"] * 11 + ["about"])
ALL = " ".join(["all"] * 12)

conformance = []
findings = []


def add(case, into=conformance):
    case["id"] = f"{len(into) + 1:04d} " + case["id"]
    into.append(case)


# ---------------------------------------------------------------- published vectors
seed_abandon = o.bip39_seed(ABANDON)
published = [
    ("bitcoin", "m/84'/0'/0'/0/0", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "BIP84"),
    ("bitcoin", "m/84'/0'/0'/0/1", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", "BIP84"),
    ("bitcoin", "m/84'/0'/0'/1/0", "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "BIP84"),
    ("bitcoin", "m/86'/0'/0'/0/0", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", "BIP86"),
    ("bitcoin", "m/86'/0'/0'/0/1", "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh", "BIP86"),
    ("bitcoin", "m/86'/0'/0'/1/0", "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", "BIP86"),
    ("bitcoin", "m/49'/1'/0'/0/0", "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", "BIP49"),
    ("dash", "m/9'/5'/17'/0'/0'/0", "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs", "DIP18"),
    ("dash", "m/9'/5'/17'/0'/0'/1", "dash1kzjl7qzxy9lar37j8r37z3kvt07epqe20ckxfezw", "DIP18"),
    ("dash", "m/9'/5'/17'/0'/1'/0", "dash1kpkeye606ez89g7lelp7hnldwwpt76va0v3j6x28", "DIP18"),
]
for coin, path, address, source in published:
    add({"t": "addr", "id": f"{source} {path}", "coin": coin, "phrase": ABANDON, "pass": "",
         "path": path, "address": address, "search": [10, 100], "found": path})
add({"t": "fp", "id": "fingerprint of BIP84's root key", "phrase": ABANDON, "pass": "", "fp": "73c5da0a"})
add({"t": "fp", "id": "SLIP-0014 fingerprint 5c9e228d", "phrase": ALL, "pass": "", "fp": "5c9e228d"})

slip = (REFS / "slip-0014.md").read_text() + (REFS / "slip-0014-addresses.md").read_text()
kinds = {"m/44'/0'/0'": "bitcoin", "m/49'/0'/0'": "bitcoin", "m/84'/0'/0'": "bitcoin",
         "m/86'/0'/0'": "bitcoin", "m/44'/1'/0'": "bitcoin", "m/49'/1'/0'": "bitcoin",
         "m/84'/1'/0'": "bitcoin", "m/44'/5'/0'": "dash", "m/44'/2'/0'": "litecoin",
         "m/44'/60'/0'": "ethereum"}
seen = set()
for section in re.split(r"\n#+ ", slip):
    account = re.search(r"`?(m/\d+'/\d+'/0')(?:/0/i)?`?", section)
    if not account or account.group(1) not in kinds or "Groestl" in section[:40]:
        continue
    for index, address in re.findall(r"^\s*(\d)\s*\|\s*`([^`]+)`", section, re.M):
        path = f"{account.group(1)}/0/{index}"
        if (path, address) in seen:
            continue
        seen.add((path, address))
        add({"t": "addr", "id": f"SLIP-0014 {path}", "coin": kinds[account.group(1)], "phrase": ALL,
             "pass": "", "path": path, "address": address, "search": [10, 100], "found": path})

# BIP39 vectors: the master fingerprint of each Trezor vector with "TREZOR" (oracle).
for entropy, mnemonic, _, _ in json.loads((REFS / "bip39-vectors.json").read_text())["english"]:
    add({"t": "fp", "id": f"BIP39 vector {entropy[:8]} fingerprint", "phrase": mnemonic,
         "pass": "TREZOR", "fp": o.fingerprint(o.bip39_seed(mnemonic, "TREZOR"))})

# ---------------------------------------------------------------- mhfe's own address table
table = (MHFE / "src/wallet/known_answers/addresses.rs").read_text()
coin_ids = {"Bitcoin": "bitcoin", "Ethereum": "ethereum", "Xrp": "xrp", "Tron": "tron",
            "Zcash": "zcash", "Dogecoin": "dogecoin", "BitcoinCash": "bitcoin-cash",
            "Litecoin": "litecoin", "EthereumClassic": "ethereum-classic", "Cosmos": "cosmos",
            "Injective": "injective", "Dash": "dash"}
rows = re.findall(r'at\(\s*Coin::(\w+),\s*"([^"]+)",\s*"([^"]+)",', table)
rows += [("Bitcoin", "m/84'/0'/0'/0/0", "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu", "TREZOR")]
assert len(rows) == 43, len(rows)


def kind_of(coin, address, path):
    purpose = path.split("/")[1]
    if coin in ("ethereum", "ethereum-classic", "tron", "injective"):
        return "keccak", False
    if coin == "dash" and purpose == "9'":
        return "dash-platform", address.startswith("t")
    if coin == "bitcoin-cash" and address.startswith("1"):
        return "p2pkh-legacy", False
    testnet = coin == "bitcoin" and path.split("/")[2] == "1'"
    return {"44'": "p2pkh", "49'": "p2sh-p2wpkh", "84'": "p2wpkh", "86'": "p2tr"}[purpose], testnet


mismatches = 0
for row in rows:
    coin_name, path, address = row[:3]
    passphrase = row[3] if len(row) > 3 else ""
    coin = coin_ids[coin_name]
    kind, testnet = kind_of(coin, address, path)
    if kind == "p2pkh-legacy":
        computed = o.address_at(ABANDON, passphrase, "bitcoin-cash-legacy", "p2pkh", path)
    else:
        computed = o.address_at(ABANDON, passphrase, coin, kind, path, testnet)
    if computed != address:
        mismatches += 1
        print(f"TABLE MISMATCH {coin} {path}: table {address} oracle {computed}")
    # The search finds the address at the table's path, or at an earlier one of the same key.
    add({"t": "addr", "id": f"mhfe table {coin} {path}", "coin": coin, "phrase": ABANDON,
         "pass": passphrase, "path": path, "address": address, "search": [10, 100], "found": path})
print(f"mhfe address table: {len(rows)} rows recomputed by the oracle, {mismatches} mismatches")

# ---------------------------------------------------------------- differential cases
def entropy(label, size):
    return hashlib.sha256(label.encode()).digest()[:size]


phrases = [o.mnemonic_from_entropy(entropy(f"aud024 phrase {i}", size))
           for i, size in enumerate([16, 20, 24, 28, 32, 32])]
passphrases = ["", "TREZOR", "Café ﬁ ＰÅ① \U0001f510 й", "ﷺ"]
types = [
    ("bitcoin", "p2pkh", "44'/0'", False), ("bitcoin", "p2sh-p2wpkh", "49'/0'", False),
    ("bitcoin", "p2wpkh", "84'/0'", False), ("bitcoin", "p2tr", "86'/0'", False),
    ("bitcoin", "p2pkh", "44'/1'", True), ("bitcoin", "p2sh-p2wpkh", "49'/1'", True),
    ("bitcoin", "p2wpkh", "84'/1'", True), ("bitcoin", "p2tr", "86'/1'", True),
    ("litecoin", "p2pkh", "44'/2'", False), ("litecoin", "p2sh-p2wpkh", "49'/2'", False),
    ("litecoin", "p2wpkh", "84'/2'", False), ("dogecoin", "p2pkh", "44'/3'", False),
    ("dash", "p2pkh", "44'/5'", False), ("zcash", "p2pkh", "44'/133'", False),
    ("bitcoin-cash", "p2pkh", "44'/145'", False), ("xrp", "p2pkh", "44'/144'", False),
    ("cosmos", "p2pkh", "44'/118'", False), ("ethereum", "keccak", "44'/60'", False),
    ("ethereum-classic", "keccak", "44'/61'", False), ("tron", "keccak", "44'/195'", False),
    ("injective", "keccak", "44'/60'", False),
    ("dash", "dash-platform", "9'/5'/17'", False), ("dash", "dash-platform", "9'/1'/17'", True),
]
spots = [(0, 0, 0), (9, 1, 99), (3, 1, 7), (0, 1, 42)]
count = 0
for p_index, phrase in enumerate(phrases):
    for q_index, passphrase in enumerate(passphrases):
        if (p_index + q_index) % 2:  # half of the pairs keeps the run short
            continue
        seed = o.bip39_seed(phrase, passphrase)
        for coin, kind, root, testnet in types:
            for account, chain, index in spots:
                chain_step = f"{chain}'" if kind == "dash-platform" else f"{chain}"
                path = f"m/{root}/{account}'/{chain_step}/{index}"
                address = o.address_at(phrase, passphrase, coin, kind, path, testnet, seed=seed)
                add({"t": "addr", "id": f"diff {coin} {kind} {path} phrase{p_index} pass{q_index}",
                     "coin": coin, "phrase": phrase, "pass": passphrase, "path": path,
                     "address": address, "search": [10, 100], "found": path})
                count += 1
        add({"t": "fp", "id": f"diff fingerprint phrase{p_index} pass{q_index}", "phrase": phrase,
             "pass": passphrase, "fp": o.fingerprint(seed)})
print(f"differential address cases: {count}")

# Boundary paths: the last ordinary index, the last hardened account, outside the default search.
seed = o.bip39_seed(phrases[4], "")
for coin, kind, root, testnet in types[:4] + types[17:18] + types[21:22]:
    for path in [f"m/{root}/2147483647'/0/2147483647", f"m/{root}/0'/1/2147483647",
                 f"m/{root}/10'/0/0"]:
        if kind == "dash-platform":
            path = path.replace("/0/", "/0'/").replace("/1/", "/1'/")
        address = o.address_at(phrases[4], "", coin, kind, path, testnet, seed=seed)
        add({"t": "addr", "id": f"boundary {coin} {kind} {path}", "coin": coin,
             "phrase": phrases[4], "pass": "", "path": path, "address": address,
             "search": [10, 100], "found": None})
# Index 100 and account 10 lie just outside the default search; index 99, account 9 inside.
address = o.address_at(phrases[4], "", "bitcoin", "p2wpkh", "m/84'/0'/9'/1/100", seed=seed)
add({"t": "addr", "id": "index 100 is outside the default search", "coin": "bitcoin",
     "phrase": phrases[4], "pass": "", "path": "m/84'/0'/9'/1/100", "address": address,
     "search": [10, 100], "found": None})
add({"t": "addr", "id": "index 100 is inside 101 indexes", "coin": "bitcoin", "phrase": phrases[4],
     "pass": "", "path": "m/84'/0'/9'/1/100", "address": address, "search": [10, 101],
     "found": "m/84'/0'/9'/1/100"})
add({"t": "not_at", "id": "a neighbouring path does not match", "coin": "bitcoin",
     "phrase": phrases[4], "pass": "", "path": "m/84'/0'/9'/1/99", "address": address})
add({"t": "not_at", "id": "the same index on the other chain does not match", "coin": "bitcoin",
     "phrase": phrases[4], "pass": "", "path": "m/84'/0'/9'/0/100", "address": address})
add({"t": "not_at", "id": "another passphrase does not match", "coin": "bitcoin",
     "phrase": phrases[4], "pass": "x", "path": "m/84'/0'/9'/1/100", "address": address})

# Hardened derivation from parent keys whose private key starts with a zero byte (BIP32 vector
# 3/4 class): parents m/84'/0' and m/9'/5'/17'/0'.
found_lz = 0
for i in range(4000):
    phrase = o.mnemonic_from_entropy(entropy(f"aud024 leading zero {i}", 16))
    seed = o.bip39_seed(phrase, "")
    for parent, child_path, coin, kind in [("m/84'/0'", "m/84'/0'/5'/0/3", "bitcoin", "p2wpkh"),
                                           ("m/9'/5'/17'/0'", "m/9'/5'/17'/0'/1'/2", "dash", "dash-platform")]:
        key, _ = o.derive(seed, parent)
        if key < (1 << 248):
            address = o.address_at(phrase, "", coin, kind, child_path, seed=seed)
            add({"t": "addr", "id": f"leading-zero parent {parent} ({i})", "coin": coin,
                 "phrase": phrase, "pass": "", "path": child_path, "address": address,
                 "search": [10, 100], "found": child_path})
            found_lz += 1
    if found_lz >= 4:
        break
print(f"leading-zero parent cases: {found_lz}")

# ---------------------------------------------------------------- parsing
def bip_list(name, heading):
    text = (REFS / name).read_text()
    part = text.split(heading, 1)[1].split("===", 1)[0]
    return re.findall(r"^\* <tt>([^<]+)</tt>", part, re.M)

# BIP173 and BIP350 valid segwit addresses: single-key ones read, others refused as not single-key.
b350 = (REFS / "bip-0350.mediawiki").read_text()
valid = re.findall(r"^\* <tt>([^<:]+)</tt>: <tt>([0-9a-f]+)</tt>", b350, re.M)
invalid_addresses = re.findall(r"^\* <tt>([^<]+)</tt>: (.+)$",
                               b350.split("The following list gives invalid segwit addresses", 1)[1].split("===", 1)[0], re.M)
for address, script in valid:
    hrp = address.lower().split("1")[0]
    if hrp not in ("bc", "tb"):
        continue
    single = (script.startswith("0014") and len(script) == 44) or (script.startswith("5120") and len(script) == 68)
    add({"t": "parse_ok" if single else "parse_err", "id": f"BIP350 valid {address[:18]}",
         "coin": "bitcoin", "text": address})
for address, why in invalid_addresses:
    if address.lower().startswith(("bc1", "tb1")):
        add({"t": "parse_err", "id": f"BIP350 invalid ({why.strip()[:30]})", "coin": "bitcoin", "text": address})
b173 = (REFS / "bip-0173.mediawiki").read_text()
for address, why in re.findall(r"^\* <tt>([^<]+)</tt>: (.+)$",
                               b173.split("The following list gives invalid segwit addresses", 1)[1].split("===", 1)[0], re.M):
    if address.lower().startswith(("bc1", "tb1")):
        add({"t": "parse_err", "id": f"BIP173 invalid ({why.strip()[:30]})", "coin": "bitcoin", "text": address})

# EIP-55: the specification's examples read; with one letter's case swapped they are refused.
eip = (REFS / "eip-55.md").read_text()
examples = [e for e in re.findall(r"0x[0-9a-fA-F]{40}", eip) if not (e[2:].islower() or e[2:].isupper())]
for example in sorted(set(examples)):
    add({"t": "parse_eq", "id": f"EIP-55 {example[:12]} lower", "coin": "ethereum", "a": example, "b": example.lower()})
    position = next(i for i, c in enumerate(example) if i > 1 and c.isalpha())
    swapped = example[:position] + example[position].swapcase() + example[position + 1:]
    add({"t": "parse_err", "id": f"EIP-55 {example[:12]} damaged", "coin": "ethereum", "text": swapped})

# CashAddr specification table: only the bitcoincash P2PKH 160-bit row reads.
cash = (REFS / "cashaddr.md").read_text()
for size, version, address, payload in re.findall(r"^\|(\d+)\|(\d+)\|([a-z]+:[a-z0-9]+)\|([0-9A-F]+)\|", cash, re.M):
    ok = address.startswith("bitcoincash:") and version == "0" and size == "20"
    add({"t": "parse_ok" if ok else "parse_err", "id": f"CashAddr spec {size}/{version} {address[:16]}",
         "coin": "bitcoin-cash", "text": address})
add({"t": "parse_eq", "id": "CashAddr without prefix, upper case", "coin": "bitcoin-cash",
     "a": "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
     "b": "QR6M7J9NJLDWWZLG9V7V53UNLR4JKMX6EYLEP8EKG2"})
add({"t": "parse_err", "id": "CashAddr mixed case", "coin": "bitcoin-cash",
     "text": "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eyLEP8EKG2"})

# DIP-18: the P2SH example and the Bech32 form are refused; upper case reads; mixed case refused.
add({"t": "parse_err", "id": "DIP18 P2SH example refused", "coin": "dash", "text": "dash1sppl5xpu70aka8nacc4kj2htflydspzkxch4cad6"})
add({"t": "parse_eq", "id": "DIP18 upper case", "coin": "dash", "a": "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs",
     "b": "DASH1KRMA5Z3TTJ75LA4M93XCNDNA9ULLAMQ9Y5E9N5RS"})
add({"t": "parse_err", "id": "DIP18 mixed case", "coin": "dash", "text": "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5RS"})
h = bytes.fromhex("f7da0a2b5cbd4ff6bb2c4d89b67d2f3ffeec0525")
add({"t": "parse_err", "id": "DIP18 payload with a Bech32 checksum", "coin": "dash",
     "text": o.bech32_encode("dash", o.convertbits(b"\xb0" + h, 8, 5), o.BECH32)})
add({"t": "parse_err", "id": "DIP18 other hrp", "coin": "dash",
     "text": o.bech32_encode("dashx", o.convertbits(b"\xb0" + h, 8, 5), o.BECH32M)})
add({"t": "parse_type", "id": "DIP18 testnet type and roots", "coin": "dash",
     "text": "tdash1krma5z3ttj75la4m93xcndna9ullamq9y5fzq2j7", "type": "testnet, Platform payment (DIP17)",
     "roots": "[[9, 1, 17]]"})

# Base58Check refusals and versions.
pk = bytes(range(20))
for coin, payload, why in [
    ("bitcoin", b"\x05" + pk[:19], "19-byte hash"), ("bitcoin", b"\x00" + pk + b"\x00", "21-byte hash"),
    ("dogecoin", b"\x16" + pk, "Dogecoin P2SH"), ("zcash", b"\x1c\xbd" + pk, "Zcash t3"),
    ("dash", b"\x10" + pk, "Dash P2SH 7..."), ("litecoin", b"\x3a" + pk, "Litecoin testnet"),
    ("tron", b"\xa0" + pk, "Tron other version"), ("bitcoin-cash", b"\x05" + pk, "BCH legacy P2SH"),
]:
    add({"t": "parse_err", "id": f"base58 {why}", "coin": coin, "text": o.base58check(payload)})
add({"t": "parse_err", "id": "XRP with the Bitcoin alphabet", "coin": "xrp", "text": o.base58check(b"\x00" + pk)})
add({"t": "parse_ok", "id": "XRP with its alphabet", "coin": "xrp", "text": o.base58check(b"\x00" + pk, o.RIPPLE)})
add({"t": "parse_type", "id": "Litecoin 3... read as nested SegWit", "coin": "litecoin",
     "text": o.base58check(b"\x05" + pk), "type": "nested SegWit (BIP49)", "roots": "[[49, 2]]"})
add({"t": "parse_type", "id": "Bitcoin Cash legacy two roots", "coin": "bitcoin-cash",
     "text": o.base58check(b"\x00" + pk), "type": "", "roots": "[[44, 145], [44, 0]]"})
add({"t": "parse_type", "id": "Ethereum Classic two roots", "coin": "ethereum-classic",
     "text": "0x" + pk.hex(), "type": "", "roots": "[[44, 61], [44, 60]]"})
add({"t": "parse_err", "id": "Cosmos with the Injective hrp", "coin": "cosmos",
     "text": o.bech32_encode("inj", o.convertbits(pk, 8, 5), o.BECH32)})
add({"t": "parse_err", "id": "Injective Bech32m", "coin": "injective",
     "text": o.bech32_encode("inj", o.convertbits(pk, 8, 5), o.BECH32M)})
add({"t": "parse_err", "id": "Litecoin Taproot not single-key here", "coin": "litecoin",
     "text": o.segwit_address("ltc", 1, bytes(32))})
add({"t": "parse_err", "id": "Bitcoin v2 program", "coin": "bitcoin", "text": o.segwit_address("bc", 2, bytes(20))})
add({"t": "parse_err", "id": "Bitcoin regtest hrp", "coin": "bitcoin", "text": o.segwit_address("bcrt", 0, pk)})

# Fingerprint text.
for text, want in [("73c5da0a", "73c5da0a"), (" 73C5DA0A ", "73c5da0a"), ("73c5da0", ""),
                   ("0x73c5da0a", ""), ("73c5da0a00", ""), ("73c5 da0a", "")]:
    add({"t": "fp_text", "id": f"fingerprint text {text!r}", "text": text, "want": want})

# ---------------------------------------------------------------- paths and limits
for text, display in [("m", "m"), ("m/0", "m/0"), ("m/2147483647'", "m/2147483647'"),
                      ("m/2147483647h", "m/2147483647'"), ("m/0'/1/2h/2/1000000000", "m/0'/1/2'/2/1000000000"),
                      ("m/" + "/".join(["0"] * 255), "m/" + "/".join(["0"] * 255))]:
    add({"t": "path_ok", "id": f"path {text[:40]} (depth {text.count('/')})", "text": text, "display": display})
for text in ["", "m/", "m//0", "m/-1", "m/+1", "m/2147483648", "m/2147483648'", "m/4294967296",
             "m/1''", "m/1'h", "M/0", "m/ 1", "m/0x1", "84'/0'", "m/1.5", "m/１"]:
    add({"t": "path_err", "id": f"path {text!r} refused", "text": text})
for accounts, indexes, ok in [(1, 1, True), (2**31, 2**31, True), (0, 1, False), (1, 0, False),
                              (2**31 + 1, 1, False), (1, 2**32 - 1, False)]:
    add({"t": "limits", "id": f"limits {accounts}x{indexes}", "accounts": accounts, "indexes": indexes, "ok": ok})
for coin, address, path, gap, pattern, count in [
    ("bitcoin", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "", 0, "m/84'/0'/0'-9'/0-1/0-99", "2000"),
    ("bitcoin", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "", 20, "m/84'/0'/0'-0'/0-1/0-19", "40"),
    ("ethereum-classic", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "", 0, "m/44'/{61,60}'/0'-9'/0-1/0-99", "4000"),
    ("dash", "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs", "", 7, "m/9'/5'/17'/0'-0'/0'-1'/0-6", "14"),
    ("bitcoin", "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", "m/49'/1'/0'/0/0", 0, "m/49'/1'/0'/0/0", "1"),
]:
    add({"t": "scope", "id": f"scope {coin} {pattern}", "coin": coin, "address": address, "path": path,
         "gap": gap, "pattern": pattern, "addresses": count})

# ---------------------------------------------------------------- missing-word searches (FUN-007)
def candidate_words(words, missing):
    """Every combination of list words at `missing` that passes the BIP39 checksum, in list order
    with the first missing word slowest; independent of mhfe's packing code."""
    numbers = [o.WORDS.index(w) if w in o.WORDS else 0 for w in words]
    out = []
    from itertools import product
    total = len(words) * 11
    cs = total // 33
    for values in product(range(2048), repeat=len(missing)):
        for position, value in zip(missing, values):
            numbers[position] = value
        value = 0
        for number in numbers:
            value = (value << 11) | number
        ent = (value >> cs).to_bytes((total - cs) // 8, "big")
        if (o.sha256(ent)[0] >> (8 - cs)) == value & ((1 << cs) - 1):
            out.append(values)
    return out


containers = [o.mnemonic_from_entropy(entropy(f"aud024 container {i}", size)) for i, size in
              enumerate([32, 32, 16, 20, 28])]
for c_index, container in enumerate(containers):
    words = container.split()
    for missing in ([len(words) - 1], [2], [0, len(words) - 1]) if c_index < 2 else ([5],):
        if len(missing) == 2 and c_index == 1:
            continue
        typed = " ".join("?" if i in missing else w for i, w in enumerate(words))
        cands = candidate_words(words, missing)
        add({"t": "candidates", "id": f"candidates container{c_index} missing {missing}", "written": typed,
             "count": len(cands), "missing": [m + 1 for m in missing]})
        cseed = o.bip39_seed(container, "")
        add({"t": "decoy", "id": f"decoy fingerprint container{c_index} missing {missing}", "kind": "fingerprint",
             "written": typed, "fp": o.fingerprint(cseed), "pass": "", "gap": 20, "container": container})
        add({"t": "decoy", "id": f"decoy other passphrase container{c_index} missing {missing}", "kind": "fingerprint",
             "written": typed, "fp": o.fingerprint(cseed), "pass": "x", "gap": 20, "container": None})
        if len(missing) == 1:
            path = "m/84'/0'/3'/1/17"
            address = o.address_at(container, "", "bitcoin", "p2wpkh", path, seed=cseed)
            add({"t": "decoy", "id": f"decoy address container{c_index} missing {missing}", "kind": "address",
                 "written": typed, "coin": "bitcoin", "address": address, "path": "", "pass": "", "gap": 20,
                 "container": container, "found_path": path})
        else:
            # Two missing words: the first account only, within the gap.
            path = "m/84'/0'/0'/1/4"
            address = o.address_at(container, "", "bitcoin", "p2wpkh", path, seed=cseed)
            add({"t": "decoy", "id": f"decoy address in gap 5 container{c_index} missing {missing}", "kind": "address",
                 "written": typed, "coin": "bitcoin", "address": address, "path": "", "pass": "", "gap": 5,
                 "container": container, "found_path": path})
            add({"t": "decoy", "id": f"decoy address beyond gap 4 container{c_index} missing {missing}", "kind": "address",
                 "written": typed, "coin": "bitcoin", "address": address, "path": "", "pass": "", "gap": 4,
                 "container": None})
words = containers[0].split()
add({"t": "search_err", "id": "no word marked missing", "written": containers[0], "code": "INVALID_REQUEST"})
add({"t": "search_err", "id": "three words missing", "written": " ".join(["?"] * 3 + words[3:]), "code": "TOO_MANY_MISSING_WORDS"})
add({"t": "search_err", "id": "wrong word count", "written": " ".join(["?"] + words[1:-1]), "code": "INVALID_REQUEST"})
typo = " ".join(["?"] + ["zzzz"] + words[2:])
add({"t": "candidates", "id": "a word outside the list counts as missing beside ?", "written": typo,
     "count": len(candidate_words(words, [0, 1])), "missing": [1, 2]})

# ---------------------------------------------------------------- findings (expected to fail)
deep = "m/" + "/".join(["0"] * 256)
add({"t": "path_err", "id": "BIP32 depth is one byte: a path of depth 256 is refused", "text": deep}, findings)
add({"t": "path_err", "id": "a path of depth 100000 is refused", "text": "m/" + "/".join(["0"] * 100000)}, findings)

(HERE / "conformance.json").write_text(json.dumps(conformance, ensure_ascii=False, indent=0))
(HERE / "findings.json").write_text(json.dumps(findings, ensure_ascii=False, indent=0))
print(f"wrote {len(conformance)} conformance and {len(findings)} findings cases")
if mismatches:
    sys.exit(1)
