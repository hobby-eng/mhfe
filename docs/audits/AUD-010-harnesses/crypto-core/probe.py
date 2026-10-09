#!/usr/bin/env python3
"""AUD-010 crypto-core: compares the mhfe library's public API with the independent oracle.

Builds probe/ (a small Rust program that calls mhfe's public functions) in a build directory
outside the repository, with a copy of mhfe's Cargo.lock, then sends it requests and compares every
answer with oracle.py's independent computation or with the rule of the specification. Exits 1 when
any comparison fails.

    python3 probe.py [--build-dir DIR] [--only NAME[,NAME...]]

Needs CARGO_HOME and RUSTUP_HOME set as the workspace documents and cargo on PATH; builds offline.
"""

import hashlib
import os
import random
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import oracle  # noqa: E402  (the independent implementation next to this file)
from oracle import (  # noqa: E402
    HARD, WORDS, WORD_INDEX, address_for, bip39_seed, check, derive, entropy_to_words, fingerprint,
    words_to_entropy,
)

ROOT = oracle.ROOT
DEFAULT_BUILD = ROOT.parent / "tmp/claude/aud010-crypto-core/probe-build"


def build(build_dir):
    build_dir.mkdir(parents=True, exist_ok=True)
    (build_dir / "src").mkdir(exist_ok=True)
    manifest = (HERE / "probe/Cargo.toml").read_text().replace('path = "../../../../.."', f'path = "{ROOT}"')
    (build_dir / "Cargo.toml").write_text(manifest)
    shutil.copy(HERE / "probe/src/main.rs", build_dir / "src/main.rs")
    shutil.copy(ROOT / "Cargo.lock", build_dir / "Cargo.lock")
    subprocess.run(
        ["cargo", "build", "--offline", "--quiet", "--manifest-path", str(build_dir / "Cargo.toml")],
        check=True,
        env={**os.environ, "CARGO_TARGET_DIR": str(build_dir / "target")},
    )
    # Every package both locks name must have the version mhfe's own lock gives it.
    def packages(path):
        out, name = {}, None
        for line in path.read_text().splitlines():
            if line.startswith("name = "):
                name = line.split('"')[1]
            elif line.startswith("version = ") and name:
                out.setdefault(name, set()).add(line.split('"')[1])
        return out

    ours, theirs = packages(build_dir / "Cargo.lock"), packages(ROOT / "Cargo.lock")
    same = all(ours[name] == versions for name, versions in theirs.items() if name in ours)
    check("probe.lock-versions-equal-mhfe", same)
    return build_dir / "target/debug/aud010-crypto-core-probe"


class Probe:
    def __init__(self, binary):
        self.binary = binary
        self.requests = []

    def ask(self, op, *args):
        """Queues a request: str arguments go as hex UTF-8 ("-" when empty), int as decimal."""
        encoded = [str(a) if isinstance(a, int) else (a.encode().hex() if a else "-") for a in args]
        self.requests.append(" ".join([op] + encoded))
        return len(self.requests) - 1

    def run(self):
        result = subprocess.run(
            [str(self.binary)], input="\n".join(self.requests) + "\n", capture_output=True, text=True, check=True
        )
        lines = result.stdout.splitlines()
        assert len(lines) == len(self.requests), (len(lines), len(self.requests))
        answers = [line.split(" ", 1)[1] if " " in line else "" for line in lines]
        self.requests = []
        return answers


ABANDON = oracle.ABANDON
TREZOR = oracle.trezor_vectors()
# A 24-word phrase from the trezor vectors and two passphrases, one that NFKD changes.
PHRASE24 = TREZOR[11][1]
UNICODE_PASSPHRASE = "Café ﬁ ＰÅ① \U0001f510 \u0439"


def phrases_section(probe):
    asked = []
    for entropy, phrase, _ in TREZOR:
        words = phrase.split()
        variants = [
            phrase,
            phrase.upper(),
            "  " + "\t".join(words) + " \n",
            " ".join(w[:4] if len(w) > 4 else w for w in words),
            "　".join(words),
            " ".join(words),
        ]
        for variant in variants:
            asked.append((probe.ask("read", variant), "OK " + phrase, f"read {len(words)} words variant"))
    for count in (12, 15, 18, 21, 24):
        for byte in (0, 0xFF):
            phrase = entropy_to_words(bytes([byte]) * (count * 4 // 3))
            asked.append((probe.ask("read", phrase), "OK " + phrase, f"read all-{byte:02x} {count}"))
    zero12 = ABANDON.split()
    bad = {
        "11 words": " ".join(zero12[:11]),
        "13 words": " ".join(zero12 + ["abandon"]),
        "25 words": " ".join(["abandon"] * 24 + ["art"]),
        "unknown word": " ".join(zero12[:11] + ["abox"]),
        "bad checksum": " ".join(zero12[:11] + ["abandon"]),
        "three-letter prefix": " ".join(["aba"] + zero12[1:]),
        "fullwidth letters": " ".join(["ａbandon"] + zero12[1:]),
        "word with trailing letter": " ".join(["abandonx"] + zero12[1:]),
        "empty": "",
    }
    for label, text in bad.items():
        asked.append((probe.ask("read", text), "ERR INVALID_PHRASE", f"read refuses {label}"))
    asked.append((probe.ask("container", ABANDON), "OK " + ABANDON, "container 12 words as typed"))
    asked.append((probe.ask("facts", ABANDON), "OK_12_SameLength_[12]_false", "facts same-length"))
    zero24 = ("abandon " * 23 + "art").strip()
    asked.append((probe.ask("facts", zero24), "OK_24_TwentyFourWords_[12,_15,_18,_21,_24]_true", "facts 24 words"))
    ambiguous = "essence drama mule dolphin bitter rain abandon abandon able human mule relax"
    asked.append((probe.ask("detect", ambiguous), "OK[21]", "detection would also take 21 words"))
    asked.append((probe.ask("detect", zero24), "OK[]", "24 zero words detected as itself"))
    # Fingerprints: every trezor phrase with and without TREZOR, and the NFKD passphrase.
    for _, phrase, _ in TREZOR:
        for passphrase in ("", "TREZOR"):
            asked.append((probe.ask("fp", phrase, passphrase), "OK " + fingerprint(phrase, passphrase), "fingerprint"))
    asked.append((probe.ask("fp", ABANDON, UNICODE_PASSPHRASE), "OK " + fingerprint(ABANDON, UNICODE_PASSPHRASE), "fingerprint NFKD passphrase"))
    asked.append((probe.ask("fp", ABANDON + " x", ""), "ERR INVALID_PHRASE", "fingerprint refuses an invalid phrase"))
    return asked


def coin_paths():
    """(coin, purpose path prefix, coin type) for every address form the wallet module supports."""
    return [
        ("bitcoin", "m/44'/0'"), ("bitcoin", "m/49'/0'"), ("bitcoin", "m/84'/0'"), ("bitcoin", "m/86'/0'"),
        ("bitcoin", "m/44'/1'"), ("bitcoin", "m/49'/1'"), ("bitcoin", "m/84'/1'"), ("bitcoin", "m/86'/1'"),
        ("litecoin", "m/44'/2'"), ("litecoin", "m/49'/2'"), ("litecoin", "m/84'/2'"),
        ("ethereum", "m/44'/60'"), ("ethereum-classic", "m/44'/61'"), ("ethereum-classic", "m/44'/60'"),
        ("xrp", "m/44'/144'"), ("tron", "m/44'/195'"), ("zcash", "m/44'/133'"), ("dogecoin", "m/44'/3'"),
        ("bitcoin-cash", "m/44'/145'"), ("bitcoin-cash", "m/44'/0'"), ("cosmos", "m/44'/118'"),
        ("injective", "m/44'/60'"), ("dash", "m/44'/5'"), ("dash", "m/9'/5'/17'"),
    ]


def addresses_section(probe):
    asked = []
    rng = random.Random(10)
    for passphrase in ("TREZOR", UNICODE_PASSPHRASE):
        seed = bip39_seed(PHRASE24, passphrase)
        for coin, root in coin_paths():
            for account, chain, index in ((0, 0, 0), (rng.randrange(1, 10), 1, rng.randrange(1, 100)), (9, 1, 99)):
                hardened_chain = "'" if root.startswith("m/9'") else ""
                path = f"{root}/{account}'/{chain}{hardened_chain}/{index}"
                key, _ = derive(seed, path)
                for legacy in ((False, True) if coin == "bitcoin-cash" else (False,)):
                    address = address_for(coin, path, key, legacy=legacy)
                    if coin == "bitcoin-cash" and root == "m/44'/0'" and not legacy:
                        address = address  # the cashaddr form of a wallet on Bitcoin's coin type
                    asked.append((probe.ask("find", coin, address, PHRASE24, passphrase, "", 10, 100), "FOUND " + path, f"search {coin} {path}"))
                    asked.append((probe.ask("find", coin, address, PHRASE24, passphrase, path, 1, 1), "FOUND " + path, f"at path {coin} {path}"))
                    # Limits that stop just short of the account or the index find nothing.
                    if account > 0:
                        asked.append((probe.ask("find", coin, address, PHRASE24, passphrase, "", account, 100), "NONE", f"limit excludes account {coin} {path}"))
                    if index > 0:
                        asked.append((probe.ask("find", coin, address, PHRASE24, passphrase, "", 10, index), "NONE", f"limit excludes index {coin} {path}"))
                    # The same address with another passphrase or without one is not found.
                    asked.append((probe.ask("find", coin, address, PHRASE24, "", "", 10, 100), "NONE", f"no passphrase {coin} {path}"))
    seed = bip39_seed(PHRASE24, "TREZOR")
    # The highest indexes BIP32 allows, at a given path.
    for path in ("m/84'/0'/2147483647'/0/2147483647", "m/44'/60'/0'/1/2147483647", "m/9'/5'/17'/2147483647'/1'/2147483647"):
        coin = {"m/84": "bitcoin", "m/44": "ethereum", "m/9'": "dash"}[path[:4]]
        address = address_for(coin, path, derive(seed, path)[0])
        asked.append((probe.ask("find", coin, address, PHRASE24, "TREZOR", path, 1, 1), "FOUND " + path, f"highest index {path}"))
    # DIP-0018's published testnet strings encode the mainnet keys' HASH160: read as testnet
    # Platform addresses, not found under testnet coin type 1, found at the mainnet path when given.
    for tail, _, _, _, _, testnet in oracle.DIP17_VECTORS:
        path = f"m/9'/5'/17'/{tail}"
        asked.append((probe.ask("parse", "dash", testnet), "OK DashPlatform testnet,_Platform_payment_(DIP17)", f"DIP18 testnet parse {tail}"))
        asked.append((probe.ask("find", "dash", testnet, ABANDON, "", "", 10, 100), "NONE", f"DIP18 testnet not under coin type 1 {tail}"))
        asked.append((probe.ask("find", "dash", testnet, ABANDON, "", path, 1, 1), "FOUND " + path, f"DIP18 testnet at given path {tail}"))
    asked.append((probe.ask("parse", "dash", oracle.DIP18_P2SH[1]), "ERR INVALID_ADDRESS", "DIP18 P2SH refused"))
    # The same index on different paths gives different addresses, each found on its own path.
    for path in ("m/44'/0'/0'/0/5", "m/49'/0'/0'/0/5", "m/84'/0'/0'/0/5", "m/86'/0'/0'/0/5", "m/84'/0'/0'/1/5", "m/84'/0'/1'/0/5"):
        address = address_for("bitcoin", path, derive(seed, path)[0])
        asked.append((probe.ask("find", "bitcoin", address, PHRASE24, "TREZOR", "", 10, 100), "FOUND " + path, f"same index {path}"))
    return asked


def swap_first_letter(address):
    """The EIP-55 address with the case of its first letter changed."""
    i = next(i for i in range(2, len(address)) if address[i].isalpha())
    return address[:i] + address[i].swapcase() + address[i + 1 :]


def address_rules_section(probe):
    asked = []
    seed = bip39_seed(ABANDON, "")
    k = lambda path: derive(seed, path)[0]
    bc1q = address_for("bitcoin", "m/84'/0'/0'/0/0", k("m/84'/0'/0'/0/0"))
    ltc1q = address_for("litecoin", "m/84'/2'/0'/0/0", k("m/84'/2'/0'/0/0"))
    cash = address_for("bitcoin-cash", "m/44'/145'/0'/0/0", k("m/44'/145'/0'/0/0"))
    eth = address_for("ethereum", "m/44'/60'/0'/0/0", k("m/44'/60'/0'/0/0"))
    cosmos = address_for("cosmos", "m/44'/118'/0'/0/0", k("m/44'/118'/0'/0/0"))
    dash_platform = address_for("dash", "m/9'/5'/17'/0'/0'/0", k("m/9'/5'/17'/0'/0'/0"))
    h = oracle.hash160(oracle.compressed(oracle.point_mul(k("m/84'/0'/0'/0/0"))))
    # Script and multisig forms, built from the same public data.
    p2wsh = oracle.segwit_address("bc", 0, hashlib.sha256(b"\x51").digest())
    ltc_p2wsh = oracle.segwit_address("ltc", 0, hashlib.sha256(b"\x51").digest())
    ltc_p2tr = oracle.segwit_address("ltc", 1, bytes(range(32)))
    bc_v2 = oracle.segwit_address("bc", 2, bytes(range(32)))
    regtest = oracle.segwit_address("bcrt", 0, h)
    cash_p2sh = oracle.cashaddr(h, version_byte=8)
    zcash_t3 = oracle.base58check(b"\x1c\xbd" + h)
    doge_p2sh = oracle.base58check(b"\x16" + h)
    cosmos_m = oracle.bech32_encode("cosmos", oracle.convert_bits(h, 8, 5), oracle.BECH32M_CONST)
    dash_platform_bech32 = oracle.bech32_encode("dash", oracle.convert_bits(b"\xb0" + h, 8, 5), oracle.BECH32_CONST)
    dash_p2sh_platform = oracle.bech32_encode("dash", oracle.convert_bits(b"\x80" + h, 8, 5), oracle.BECH32M_CONST)
    mixed = lambda text: text[:5] + text[5:].upper()
    cases = [
        ("bitcoin", bc1q.upper(), "OK P2wpkh native_SegWit_(BIP84)"),
        ("bitcoin", mixed(bc1q), "ERR INVALID_ADDRESS"),
        ("bitcoin", bc1q[:-1] + ("q" if bc1q[-1] != "q" else "p"), "ERR INVALID_ADDRESS"),
        ("bitcoin", p2wsh, "ERR INVALID_ADDRESS"),
        ("bitcoin", bc_v2, "ERR INVALID_ADDRESS"),
        ("bitcoin", regtest, "ERR INVALID_ADDRESS"),
        ("bitcoin", ltc1q, "ERR INVALID_ADDRESS"),
        ("bitcoin", eth, "ERR INVALID_ADDRESS"),
        ("bitcoin", cash, "ERR INVALID_ADDRESS"),
        ("litecoin", bc1q, "ERR INVALID_ADDRESS"),
        ("litecoin", ltc_p2wsh, "ERR INVALID_ADDRESS"),
        ("litecoin", ltc_p2tr, "ERR INVALID_ADDRESS"),
        ("bitcoin-cash", cash.upper(), "OK P2pkh"),
        ("bitcoin-cash", cash.split(":")[1], "OK P2pkh"),
        ("bitcoin-cash", cash[:14] + cash[14:].upper(), "ERR INVALID_ADDRESS"),
        ("bitcoin-cash", cash_p2sh, "ERR INVALID_ADDRESS"),
        ("bitcoin-cash", "bchtest:" + cash.split(":")[1], "ERR INVALID_ADDRESS"),
        ("zcash", zcash_t3, "ERR INVALID_ADDRESS"),
        ("dogecoin", doge_p2sh, "ERR INVALID_ADDRESS"),
        ("ethereum", eth.lower(), "OK Keccak"),
        ("ethereum", "0x" + eth[2:].upper(), "OK Keccak"),
        ("ethereum", swap_first_letter(eth), "ERR INVALID_ADDRESS"),
        ("cosmos", cosmos.upper(), "OK P2pkh"),
        ("cosmos", cosmos_m, "ERR INVALID_ADDRESS"),
        ("injective", cosmos, "ERR INVALID_ADDRESS"),
        ("dash", dash_platform.upper(), "OK DashPlatform Platform_payment_(DIP17)"),
        ("dash", dash_platform_bech32, "ERR INVALID_ADDRESS"),
        ("dash", dash_p2sh_platform, "ERR INVALID_ADDRESS"),
        ("dash", "dash1zabc", "ERR INVALID_ADDRESS"),
        ("monero", bc1q, "ERR INVALID_COIN"),
        ("", bc1q, "ERR INVALID_COIN"),
    ]
    for coin, address, expected in cases:
        answer_index = probe.ask("parse", coin, address)
        asked.append((answer_index, expected, f"parse {coin} {address[:24]}", "prefix"))
    paths = {
        "m": "OK m",
        "m/0": "OK m/0",
        "m/2147483647'": "OK m/2147483647'",
        "m/2147483647h": "OK m/2147483647'",
        "m/2147483648": "ERR INVALID_DERIVATION_PATH",
        "m/-1": "ERR INVALID_DERIVATION_PATH",
        "m/1.5": "ERR INVALID_DERIVATION_PATH",
        "m/+1": "ERR INVALID_DERIVATION_PATH",
        "m//1": "ERR INVALID_DERIVATION_PATH",
        "m/1/": "ERR INVALID_DERIVATION_PATH",
        "M/1": "ERR INVALID_DERIVATION_PATH",
        "m/ 1": "ERR INVALID_DERIVATION_PATH",
        "m/1''": "ERR INVALID_DERIVATION_PATH",
        "m/99999999999999999999": "ERR INVALID_DERIVATION_PATH",
    }
    for text, expected in paths.items():
        asked.append((probe.ask("path", text), expected, f"path {text!r}"))
    for accounts, indexes, expected in ((0, 1, "ERR"), (1, 0, "ERR"), (1, 1, "OK 1 1"), (2**31, 2**31, f"OK {2**31} {2**31}"), (2**31 + 1, 1, "ERR"), (1, 2**31 + 1, "ERR")):
        asked.append((probe.ask("limits", accounts, indexes), expected, f"limits {accounts} {indexes}", "prefix"))
    describes = [
        ("bitcoin", bc1q, "", "OK m/84'/0'/0'-9'/0-1/0-99 2000 false native_SegWit_(BIP84)"),
        ("bitcoin-cash", cash, "", "OK m/44'/{145,0}'/0'-9'/0-1/0-99 4000 false -"),
        ("ethereum-classic", eth, "", "OK m/44'/{61,60}'/0'-9'/0-1/0-99 4000 false -"),
        ("dash", dash_platform, "", "OK m/9'/5'/17'/0'-9'/0'-1'/0-99 2000 false Platform_payment_(DIP17)"),
        ("bitcoin", bc1q, "m/84'/0'/0'/0/5", "OK m/84'/0'/0'/0/5 1 true native_SegWit_(BIP84)"),
        ("bitcoin", bc1q, "m/84'/0'/x", "ERR INVALID_DERIVATION_PATH"),
        ("xrp", bc1q, "", "ERR INVALID_ADDRESS"),
        ("Bitcoin", bc1q, "", "OK m/84'/0'/0'-9'/0-1/0-99 2000 false native_SegWit_(BIP84)"),
    ]
    for coin, address, path, expected in describes:
        asked.append((probe.ask("describe", coin, address, path), expected, f"describe {coin} {path}"))
    return asked


def wallet_check_section(probe):
    asked = []
    for counter, passphrase, passes in ((76562, "TREZOR", True), (98918, "", True), (76562, "", False), (98918, "TREZOR", False)):
        phrase = entropy_to_words(bytes(24) + counter.to_bytes(8, "big"))
        asked.append((probe.ask("wcpass", phrase, passphrase), f"OK {str(passes).lower()}", f"wallet check pass {counter} {passphrase!r}"))
        expected = f"OK {str(passes).lower()}" if passphrase else "ERR WALLET_CHECK_NEEDS_PASSPHRASE"
        asked.append((probe.ask("wcverify", phrase, passphrase), expected, f"wallet check verify {counter} {passphrase!r}"))
    asked.append((probe.ask("wcverify", ABANDON, "TREZOR"), "ERR INVALID_WORD_COUNT", "wallet check refuses 12 words"))
    asked.append((probe.ask("wcdraw", ""), "ERR WALLET_CHECK_NEEDS_PASSPHRASE", "draw with check refuses an empty passphrase"))
    asked.append((probe.ask("wcdraw", "TREZOR"), "OK true", "draw with check takes a passphrase"))
    return asked


def wallet_check_rule_reproduction(probe):
    """Reproduces the AUD-010 crypto-core wallet-check finding; passes while the defect is present.

    short_reading_wallet_check.py found a public passphrase with which the profile's digest of the
    12-word original of zero-12, computed with BE32(128), begins with 16 zero bits. The rehearsal's
    compare() calls phrase_passes, which reports this as a pass and takes an empty passphrase, while
    verify (the browser wallet's rule) refuses both. After a fix these answers change by design.
    """
    asked = []
    short_pass = "aud010 public probe 11656"
    asked.append((probe.ask("wcpass", ABANDON, short_pass), "OK true", "phrase_passes takes a 12-word phrase"))
    asked.append((probe.ask("wcverify", ABANDON, short_pass), "ERR INVALID_WORD_COUNT", "verify refuses the same 12-word phrase"))
    asked.append((probe.ask("wcpass", PHRASE24, ""), "OK false", "phrase_passes takes an empty passphrase"))
    asked.append((probe.ask("wcverify", PHRASE24, ""), "ERR WALLET_CHECK_NEEDS_PASSPHRASE", "verify refuses an empty passphrase"))
    return asked


def fingerprint_reading_reproduction(probe):
    """Reproduces the AUD-010 crypto-core phrase-reading finding; passes while the defect is present.

    master_fingerprint (and find_address, through the same master key) reads a phrase with the
    bip39 crate's strict parser, while read_phrase, the wallet check and containers read it as the
    specification's "Reading words" asks: any letter case, four-letter prefixes. The browser's
    MhfeWallet.fingerprint and walletCheck take the same `phrase` with these two rules.
    """
    asked = []
    upper = ABANDON.upper()
    prefixes = " ".join(w[:4] for w in ABANDON.split())
    seed = bip39_seed(ABANDON, "")
    bc1q = address_for("bitcoin", "m/84'/0'/0'/0/0", derive(seed, "m/84'/0'/0'/0/0")[0])
    for label, text in (("capitals", upper), ("four-letter prefixes", prefixes)):
        asked.append((probe.ask("read", text), "OK " + ABANDON, f"read_phrase takes {label}"))
        asked.append((probe.ask("wcpass", text, ""), "OK false", f"phrase_passes takes {label}"))
        asked.append((probe.ask("fp", text, ""), "ERR INVALID_PHRASE", f"master_fingerprint refuses {label}"))
        asked.append((probe.ask("find", "bitcoin", bc1q, text, "", "", 1, 1), "ERR INVALID_PHRASE", f"find_address refuses {label}"))
    return asked


def repair_section(probe, rng):
    asked = []
    containers = [
        oracle.json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())["container"],
        oracle.json.loads((ROOT / "tests/fixtures/suite4-vectors/same-length-nonzero-12.json").read_text())["container"],
        oracle.json.loads((ROOT / "tests/fixtures/suite4-vectors/same-length-nonzero-21.json").read_text())["container"],
        oracle.json.loads((ROOT / "tests/fixtures/suite4-vectors/same-length-zero-18.json").read_text())["container"],
        oracle.json.loads((ROOT / "tests/fixtures/suite4-vectors/same-length-zero-15.json").read_text())["container"],
    ]
    stats = {"within": 0, "beyond": 0, "beyond-refused": 0, "beyond-original": 0, "beyond-other": 0}
    for container in containers:
        for k in (2, 4, 6, 8):
            card = oracle.repair_words(container, k)
            asked.append((probe.ask("rwords", container, k), "OK " + card, f"repair words k={k}"))
            plate, card_words = container.split(), card.split()
            n = len(plate) + k
            codeword = [WORD_INDEX[w] for w in plate + card_words]
            for trial in range(40):
                within = trial < 25
                while True:
                    e = rng.randrange(0, k // 2 + 2)
                    s = rng.randrange(0, k + 2)
                    if within == (2 * e + s <= k) and e + s <= n and e + s > 0:
                        break
                positions = rng.sample(range(n), e + s)
                erased = sorted(positions[:s])
                received = list(codeword)
                words = plate + card_words
                typed = list(words)
                for p in erased:
                    received[p] = 0
                    typed[p] = "?"
                for p in positions[s:]:
                    value = rng.choice([v for v in range(2048) if v != codeword[p]])
                    received[p] = value
                    typed[p] = WORDS[value] if rng.random() < 0.7 else WORDS[value][:4]
                plate_text = " ".join(typed[: len(plate)])
                card_text = " ".join(f"{i + 1}/{k} {w}" for i, w in enumerate(typed[len(plate) :]))
                if rng.random() < 0.5:
                    card_text = "MHFE-REPAIR-1 " + card_text
                decoded = oracle.rs_decode(received, erased, k)
                if within:
                    expected_container = container
                    assert decoded == codeword
                    stats["within"] += 1
                else:
                    stats["beyond"] += 1
                    expected_container = None
                    if decoded is not None:
                        candidate = " ".join(WORDS[v] for v in decoded[: len(plate)])
                        try:
                            words_to_entropy(candidate)
                            expected_container = candidate
                        except ValueError:
                            expected_container = None
                index = probe.ask("repair", plate_text, card_text)
                if not within:
                    outcome = "refused" if expected_container is None else ("original" if expected_container == container else "other")
                    stats["beyond-" + outcome] += 1
                if expected_container is None:
                    asked.append((index, "ERR REPAIR_NOT_POSSIBLE", f"repair beyond bound k={k} e={e} s={s} refused"))
                elif within:
                    # Every damaged word is reported with its place, plate and card apart.
                    listed = lambda places: "[" + ",_".join(str(p) for p in places) + "]"
                    plate_places = sorted(p + 1 for p in positions if p < len(plate))
                    card_places = sorted(p + 1 - len(plate) for p in positions if p >= len(plate))
                    expected = f"OK_{expected_container.replace(' ', '_')}|{listed(plate_places)}|{listed(card_places)}|{e + s}"
                    asked.append((index, expected, f"repair k={k} e={e} s={s}"))
                else:
                    asked.append((index, "OK_" + expected_container.replace(" ", "_") + "|", f"repair beyond bound k={k} e={e} s={s} as decoded", "prefix"))
    asked.append((probe.ask("repair", " ".join(containers[0].split()[:23]), oracle.repair_words(containers[0], 4)), "ERR INVALID_CONTAINER", "repair refuses 23 plate words"))
    asked.append((probe.ask("repair", containers[0], "labor extra abandon"), "ERR INVALID_REPAIR_WORDS", "repair refuses 3 card words"))
    asked.append((probe.ask("rwords", containers[0], 3), "ERR INVALID_REPAIR_WORDS", "repair words refuse k=3"))
    asked.append((probe.ask("rwords", ABANDON + " zoo", 4), "ERR INVALID_CONTAINER", "repair words refuse an invalid container"))
    print(f"  repair trials: {stats}")
    return asked


def check_word_section(probe, rng):
    asked = []
    eff_lines = (ROOT / "vendor/eff-large-wordlist/eff_large_wordlist.txt").read_text().splitlines()
    eff = [line.split("\t")[1] for line in eff_lines]
    asked.append((probe.ask("eff"), "OK " + " ".join(eff), "EFF list as vendored, in dice order"))
    for _ in range(200):
        d = [rng.randrange(7776) for _ in range(5)]
        c = (d[0] + 5 * d[1] + 7 * d[2] + 11 * d[3] + 13 * d[4]) % 7776
        asked.append((probe.ask("cindex", *d), f"OK {c}", "check index"))
    asked.append((probe.ask("cindex", 7775, 7775, 7775, 7775, 7775), f"OK {(7775 * 37) % 7776}", "check index of 66666 x5"))
    weights = [1, 5, 7, 11, 13, 7775]  # the sixth: c - sum = 0, i.e. -1 * c

    def fix(indexes, position):
        """The unique word at `position` that makes the six fit."""
        if position == 5:
            return (sum(w * i for w, i in zip(weights[:5], indexes[:5]))) % 7776
        partial = (sum(w * i for p, (w, i) in enumerate(zip(weights[:5], indexes[:5])) if p != position) - indexes[5]) % 7776
        return (-partial * pow(weights[position], -1, 7776)) % 7776

    for _ in range(60):
        d = [rng.randrange(7776) for _ in range(5)]
        six = d + [fix(d + [0], 5)]
        password = " ".join(eff[i] for i in six)
        asked.append((probe.ask("review", password), "OK Fits None ", "review fits"))
        p = rng.randrange(6)
        erased = list(six)
        typed = password.split()
        typed[p] = "?" if rng.random() < 0.5 else "notalistword"
        asked.append((probe.ask("review", " ".join(typed)), f"OK Restorable None {p + 1}:{eff[six[p]]}", "review restores one erased word"))
        wrong = list(six)
        wrong[p] = (six[p] + rng.randrange(1, 7776)) % 7776
        repairs = ",".join(f"{q + 1}:{eff[fix(wrong, q)]}" for q in range(6))
        asked.append((probe.ask("review", " ".join(eff[i] for i in wrong)), f"OK Mismatch None {repairs}", "review lists six repairs"))
        asked.append((probe.ask("review", "  " + password.upper().replace(" ", "  ") + " "), "OK Fits Some(SpacesAndCapitals) ", "review corrects spaces and capitals"))
        asked.append((probe.ask("review", password + " extra"), "OK NotThisShape None ", "review seven words"))
    return asked


def password_section(probe):
    asked = []
    cases = {
        "public test password": "OK " + b"public test password".hex(),
        "Café": "OK " + unicodedata.normalize("NFKD", "Café").encode().hex(),
        "ﬁ①": "OK " + unicodedata.normalize("NFKD", "ﬁ①").encode().hex(),
        "a\tb": "ERR CONTROL_CHARACTER_IN_PASSWORD",
        "a b": "ERR CONTROL_CHARACTER_IN_PASSWORD",
        "a\u0085b": "ERR CONTROL_CHARACTER_IN_PASSWORD",
        "﷐": "ERR UNASSIGNED_CHARACTER",
        "": "OK " + "".encode().hex(),
        "": "ERR EMPTY_PASSWORD",
        "x" * 1024: "OK " + ("x" * 1024).encode().hex(),
        "x" * 1025: "ERR PASSWORD_TOO_LONG",
        " lead and trail ": "OK " + b" lead and trail ".hex(),
    }
    for text, expected in cases.items():
        asked.append((probe.ask("password", text), expected, f"password {text[:12]!r}"))
    return asked


def main(arguments):
    build_dir = DEFAULT_BUILD
    only = None
    while arguments:
        if arguments[0] == "--build-dir":
            build_dir, arguments = Path(arguments[1]), arguments[2:]
        elif arguments[0] == "--only":
            only, arguments = arguments[1].split(","), arguments[2:]
        else:
            sys.exit(f"unknown argument {arguments[0]}")
    probe = Probe(build(build_dir))
    rng = random.Random(20261007)
    sections = {
        "phrases": lambda: phrases_section(probe),
        "addresses": lambda: addresses_section(probe),
        "address-rules": lambda: address_rules_section(probe),
        "wallet-check": lambda: wallet_check_section(probe),
        "repair": lambda: repair_section(probe, rng),
        "check-word": lambda: check_word_section(probe, rng),
        "passwords": lambda: password_section(probe),
        "REPRODUCED-wallet-check-rule": lambda: wallet_check_rule_reproduction(probe),
        "REPRODUCED-fingerprint-reading": lambda: fingerprint_reading_reproduction(probe),
    }
    for name, section in sections.items():
        if only and name not in only:
            continue
        asked = section()
        answers = probe.run()
        failures = 0
        for entry in asked:
            index, expected, label = entry[:3]
            prefix = len(entry) > 3
            got = answers[index]
            ok = got.startswith(expected) if prefix else got == expected
            if not ok:
                failures += 1
                if failures <= 15:
                    print(f"  MISMATCH {label}: expected {expected[:160]!r}, got {got[:160]!r}")
        check(f"probe.{name}", failures == 0, f"{len(asked)} requests, {failures} mismatches")
    print(f"{len(oracle.FAILURES)} failed" + (": " + ", ".join(oracle.FAILURES) if oracle.FAILURES else ""))
    return 1 if oracle.FAILURES else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
