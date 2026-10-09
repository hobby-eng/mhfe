#!/usr/bin/env python3
"""AUD-015 R1: an independent oracle for MHFE suites 3 and 4 and the optional profiles.

Written from the specification text (mhfe_spec/README.md and vectors/profiles/README.md), not
from the implementation. Hashes come from Python's hashlib and hmac, Argon2id from the OpenSSL
command-line tool (`openssl kdf ... ARGON2ID`), the BIP39 English list from @scure/bip39 in the
workspace, pinned by the SHA-256 of the canonical english.txt. Public test data only.

    oracle.py vectors <spec-vectors-dir>      replay every published suite 3 and suite 4 transcript
                                              without Argon2 (recorded K_i) and the fast cases
    oracle.py reduced <repo-root>             reproduce the reduced-cost containers pinned in
                                              src/mhfe.rs with OpenSSL Argon2id (256 KiB, 1 pass)
    oracle.py batch <cases.json>              recompute containers that the browser core produced
                                              at the reduced cost (written by wasm_probe.mjs)
    oracle.py profiles <spec-root>            MHFE-WALLET-CHECK-SEED-1, MHFE-REPAIR-1 and
                                              MHFE-PASSWORD-CHECK-1 published vectors
    oracle.py phrases <probe-output>          compare the library's phrase reading (password-probe
                                              phrases) with the Reading words rule

Every subcommand exits non-zero on the first disagreement and prints it.
"""
import hashlib
import hmac
import json
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parents[5]
# SHA-256 of bitcoin/bips bip-0039/english.txt (2048 lines, LF), the published list.
ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
SCURE_ENGLISH = (
    WORKSPACE
    / "multi-chain-wallet-tools/node_modules/.pnpm/@scure+bip39@2.4.0/node_modules/@scure/bip39"
    / "wordlists/english.js"
)
# SHA-256 the specification gives for eff_large_wordlist.txt.
EFF_SHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"

SUITE3 = b"MHFE-BIP39-256-EXPERIMENTAL-3"
SUITE4 = b"MHFE-BIP39-LP-EXPERIMENTAL-4"
ROUNDS = 12


def fail(message):
    print(f"FAIL: {message}")
    sys.exit(1)


def check(condition, message):
    if not condition:
        fail(message)


def english_words():
    text = SCURE_ENGLISH.read_text()
    words = [w for w in re.search(r"`([^`]*)`", text).group(1).split("\n") if w]
    digest = hashlib.sha256(("\n".join(words) + "\n").encode()).hexdigest()
    check(digest == ENGLISH_SHA256, f"BIP39 English list hash {digest}")
    return words


WORDS = english_words()
INDEX = {word: i for i, word in enumerate(WORDS)}


# BIP39 -------------------------------------------------------------------------------------------


def to_mnemonic(entropy):
    bits = int.from_bytes(entropy, "big")
    ent = len(entropy) * 8
    cs = ent // 32
    checksum = hashlib.sha256(entropy).digest()[0] >> (8 - cs)
    total = (bits << cs) | checksum
    count = (ent + cs) // 11
    return " ".join(WORDS[(total >> (11 * (count - 1 - i))) & 0x7FF] for i in range(count))


def from_mnemonic(phrase):
    """Entropy of a full-word, lower-case phrase, or None when its checksum fails."""
    words = phrase.split(" ")
    count = len(words)
    total = 0
    for word in words:
        total = (total << 11) | INDEX[word]
    cs = count // 3
    ent = count * 11 - cs
    entropy = (total >> cs).to_bytes(ent // 8, "big")
    if hashlib.sha256(entropy).digest()[0] >> (8 - cs) != total & ((1 << cs) - 1):
        return None
    return entropy


ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def resolve(token):
    """The Reading words rule: exact word first, else a unique prefix of at least four letters."""
    # Letter case of the ASCII letters the English list consists of.
    token = token.translate(ASCII_LOWER)
    if token in INDEX:
        return token
    if len(token) < 4:
        return None
    matches = [word for word in WORDS if word.startswith(token)]
    return matches[0] if len(matches) == 1 else None


# MHFE ---------------------------------------------------------------------------------------------


def be32(value):
    return value.to_bytes(4, "big")


class Geometry:
    def __init__(self, suite, entropy_bytes=32):
        self.suite_id = SUITE3 if suite == 3 else SUITE4
        self.ds_salt = self.suite_id + b"/ROUND-SALT"
        self.ds_mask = self.suite_id + b"/ROUND-MASK"
        self.half = 16 if suite == 3 else entropy_bytes // 2
        self.ent = None if suite == 3 else entropy_bytes * 8

    def message(self, mem, pim, i, right):
        ent = b"" if self.ent is None else be32(self.ent)
        return be32(mem) + be32(pim) + ent + be32(i) + right

    def salt(self, message):
        # BLAKE2b with its digest length parameter set to 32 (RFC 7693), then the first 16 bytes.
        return hashlib.blake2b(self.ds_salt + message, digest_size=32).digest()[:16]

    def mask(self, key, message):
        return hmac.new(key, self.ds_mask + message, hashlib.sha256).digest()[: self.half]


def memory_kib(mem):
    return (2 + mem % 2) << (20 + mem // 2)


def passes(pim):
    return 12 * (pim + 1)


def openssl_argon2id(password, salt, kib, iterations):
    command = [
        "openssl", "kdf", "-keylen", "32",
        "-kdfopt", f"hexpass:{password.hex()}", "-kdfopt", f"hexsalt:{salt.hex()}",
        "-kdfopt", f"iter:{iterations}", "-kdfopt", f"memcost:{kib}", "-kdfopt", "lanes:4",
        "-binary", "ARGON2ID",
    ]
    key = subprocess.run(command, check=True, capture_output=True).stdout
    check(len(key) == 32, "OpenSSL Argon2id output length")
    return key


def permute(geometry, state, mem, pim, key_of, forward=True):
    """Perm or Perm^-1; key_of(i, salt) gives K_i. Returns the result and the round records."""
    half = geometry.half
    check(len(state) == 2 * half, "state size")
    left, right = state[:half], state[half:]
    records = []
    order = range(ROUNDS) if forward else range(ROUNDS - 1, -1, -1)
    for i in order:
        unchanged = right if forward else left
        message = geometry.message(mem, pim, i, unchanged)
        salt = geometry.salt(message)
        key = key_of(i, salt)
        mask = geometry.mask(key, message)
        before = (left, right)
        if forward:
            left, right = right, bytes(a ^ b for a, b in zip(left, mask))
        else:
            left, right = bytes(a ^ b for a, b in zip(right, mask)), left
        records.append(dict(i=i, message=message, salt=salt, key=key, mask=mask,
                            before=before, after=(left, right)))
    return left + right, records


def pack(entropy):
    return entropy + hashlib.sha256(entropy).digest()[: 32 - len(entropy)]


def detect(state):
    """Short lengths whose verifier passes, ascending (recovery step 3)."""
    found = []
    for words in (12, 15, 18, 21):
        n = words // 3 * 4
        if state[n:] == hashlib.sha256(state[:n]).digest()[: 32 - n]:
            found.append(words)
    return found


def readings(state):
    """Recovery with detection: [(words, verified, phrase)], the 24-word reading last."""
    short = detect(state)
    if len(short) == 1:
        n = short[0] // 3 * 4
        return [(short[0], True, to_mnemonic(state[:n]))]
    result = [(w, True, to_mnemonic(state[: w // 3 * 4])) for w in short]
    return result + [(24, False, to_mnemonic(state))]


def password_bytes(text):
    return unicodedata.normalize("NFKD", text).encode()


def encrypt(phrase, password, suite, mem, pim, argon2):
    entropy = from_mnemonic(phrase)
    if suite == 3:
        geometry, x = Geometry(3), pack(entropy)
    else:
        geometry, x = Geometry(4, len(entropy)), entropy
    y, _ = permute(geometry, x, mem, pim, lambda i, salt: argon2(password, salt), True)
    check(y != x, "fixed point")
    return to_mnemonic(y)


# Subcommands -------------------------------------------------------------------------------------


def replay_transcript(path, data=None):
    data = data if data is not None else json.loads(path.read_text())
    suite = 3 if data["suite_id"] == SUITE3.decode() else 4
    check(data["suite_id"] in (SUITE3.decode(), SUITE4.decode()), f"{path.name}: suite")
    inputs = data["inputs"]
    mem, pim = inputs["memory_level"], inputs["pim"]
    check(data["argon2"] == {"variant": "Argon2id", "version": 19, "memory_kib": memory_kib(mem),
                             "passes": passes(pim), "lanes": 4, "output_bytes": 32},
          f"{path.name}: Argon2 parameters {data['argon2']}")
    nfkd = password_bytes(inputs["password"])
    check(nfkd.hex() == inputs["password_nfkd_utf8_hex"], f"{path.name}: NFKD password bytes")
    check(inputs["password"].encode().hex() == inputs["password_utf8_hex"], f"{path.name}: UTF-8")
    entropy = from_mnemonic(inputs["phrase"])
    check(entropy is not None, f"{path.name}: phrase checksum")
    if suite == 3:
        geometry, x = Geometry(3), pack(entropy)
        packing = data["packing"]
        check(packing["state_hex"] == x.hex() and packing["entropy_hex"] == entropy.hex(),
              f"{path.name}: packing")
        check(packing["verifier_hex"] == x[len(entropy):].hex(), f"{path.name}: verifier")
    else:
        geometry, x = Geometry(4, len(entropy)), entropy
        state = data["state"]
        check(state["state_hex"] == x.hex() and state["half_bytes"] == len(x) // 2
              and state["entropy_bits"] == len(x) * 8, f"{path.name}: suite 4 state")
    keys = {}
    for direction, forward in (("encryption", True), ("decryption", False)):
        section = data[direction]
        recorded = {r["round"]: r for r in section["rounds"]}
        start = bytes.fromhex(section["input_state_hex"])

        def key_of(i, salt, recorded=recorded):
            entry = recorded[i]
            check(entry["salt_hex"] == salt.hex(), f"{path.name}: {direction} salt {i}")
            return bytes.fromhex(entry["argon2_key_hex"])

        out, records = permute(geometry, start, mem, pim, key_of, forward)
        check(out.hex() == section["output_state_hex"], f"{path.name}: {direction} output")
        check([r["i"] for r in records] == [r["round"] for r in section["rounds"]],
              f"{path.name}: {direction} round order")
        for record, entry in zip(records, section["rounds"]):
            i = record["i"]
            fields = {
                "salt_input_hex": geometry.ds_salt + record["message"],
                "mask_input_hex": geometry.ds_mask + record["message"],
                "mask_hex": record["mask"],
                "left_before_hex": record["before"][0], "right_before_hex": record["before"][1],
                "left_after_hex": record["after"][0], "right_after_hex": record["after"][1],
            }
            for name, value in fields.items():
                check(entry[name] == value.hex(), f"{path.name}: {direction} round {i} {name}")
            keys.setdefault(i, set()).add(entry["argon2_key_hex"])
    check(data["encryption"]["input_state_hex"] == x.hex(), f"{path.name}: encryption input")
    y = bytes.fromhex(data["encryption"]["output_state_hex"])
    check(data["decryption"]["input_state_hex"] == y.hex(), f"{path.name}: decryption input")
    check(data["decryption"]["output_state_hex"] == x.hex(), f"{path.name}: round trip")
    check(all(len(v) == 1 for v in keys.values()), f"{path.name}: K_i differs by direction")
    check(to_mnemonic(y) == data["container"], f"{path.name}: container words")
    if suite == 3:
        expected = [{"words": w, "verified": v, "phrase": p} for w, v, p in readings(x)]
        check(data["recovery"] == expected, f"{path.name}: recovery {data['recovery']}")
    else:
        check(data["recovery"] == {"words": len(x) // 4 * 3, "verified": False,
                                   "phrase": inputs["phrase"]}, f"{path.name}: suite 4 recovery")
    return suite


def command_vectors(root):
    root = Path(root)
    counts = {3: 0, 4: 0}
    for suite_dir in ("suite3", "suite4"):
        for path in sorted((root / suite_dir).glob("*.json")):
            if path.name in ("negative-cases.json", "validation-cases.json"):
                continue
            counts[replay_transcript(path)] += 1
    check(counts == {3: 17, 4: 10}, f"transcript counts {counts}")
    # Negative controls: one changed mask byte, salt-input byte or container word must fail.
    for suite_dir, name, mutate in (
        ("suite3", "zero-12.json", lambda d: d["encryption"]["rounds"][5].update(
            mask_hex="00" + d["encryption"]["rounds"][5]["mask_hex"][2:])),
        ("suite4", "same-length-zero-15.json", lambda d: d["decryption"]["rounds"][0].update(
            salt_input_hex=d["decryption"]["rounds"][0]["salt_input_hex"][:-2] + "ff")),
        ("suite3", "nonzero-24.json", lambda d: d.update(container="abandon " + d["container"]
                                                         .split(" ", 1)[1])),
    ):
        path = root / suite_dir / name
        data = json.loads(path.read_text())
        mutate(data)
        print(f"negative control on {name}, which must fail:")
        try:
            replay_transcript(path, data)
        except SystemExit:
            continue
        fail(f"negative control on {name} was not detected")
    # Fast cases: verifier serialization, length detection, settings.
    cases = json.loads((root / "suite3/validation-cases.json").read_text())
    serial = cases["verifier_serialization"]
    entropy = bytes.fromhex(serial["entropy_hex"])
    check(pack(entropy).hex() == serial["state_hex"], "verifier serialization")
    for case in cases["length_detection"]:
        state = bytes.fromhex(case["state_hex"])
        check(detect(state) == case["matching_short_lengths"], f"detection {case['id']}")
    for case in cases["settings"]:
        if "expected_memory_kib" in case:
            check(memory_kib(case["memory_level"]) == case["expected_memory_kib"]
                  and passes(case["pim"]) == case["expected_passes"], f"settings {case['id']}")
    # Spec text: m(MEM) series and limits.
    check([memory_kib(m) >> 20 for m in range(11)] == [2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64],
          "memory series")
    check(memory_kib(21) == 3 << 30 and memory_kib(21) < 2**32 <= memory_kib(22), "level 21/22")
    print(f"PASS vectors: {counts[3]} suite 3 and {counts[4]} suite 4 transcripts replayed "
          f"without Argon2 in both directions; {len(cases['length_detection'])} detection cases")


def rust_constant(source, name):
    match = re.search(rf"const {name}: &str =\s*((?:\"[^\"]*\"\s*)+);", source)
    check(match is not None, f"constant {name} not found")
    text = "".join(re.findall(r"\"([^\"]*)\"", match.group(1)))
    return " ".join(text.replace("\\", " ").split())


def reduced_argon2(password, salt):
    # The reduced cost of src/test_support.rs: 256 KiB and one pass, four lanes.
    return openssl_argon2id(password, salt, 256, 1)


def command_reduced(repo):
    source = (Path(repo) / "src/mhfe.rs").read_text()
    zero_12 = " ".join(["abandon"] * 11 + ["about"])
    password = password_bytes("public test password")
    pinned = {
        3: rust_constant(source, "REDUCED_COST_CONTAINER"),
        4: rust_constant(source, "REDUCED_COST_SAME_LENGTH_CONTAINER"),
    }
    for suite, expected in pinned.items():
        got = encrypt(zero_12, password, suite, 0, 0, reduced_argon2)
        check(got == expected, f"reduced suite {suite}: oracle {got!r} vs pinned {expected!r}")
    print("PASS reduced: OpenSSL Argon2id at 256 KiB/1 pass reproduces REDUCED_COST_CONTAINER "
          "and REDUCED_COST_SAME_LENGTH_CONTAINER")


def command_batch(path):
    cases = json.loads(Path(path).read_text())
    for number, case in enumerate(cases):
        password = bytes.fromhex(case["password_nfkd_hex"]) if "password_nfkd_hex" in case \
            else password_bytes(case["password"])
        got = encrypt(case["phrase"], password, 4 if case["sameLength"] else 3, 0, case["pim"],
                      reduced_argon2)
        check(got == case["container"],
              f"case {number} ({case['label']}): core {case['container']!r}, oracle {got!r}")
        if "recoveredAs24" in case:
            # The 24-word reading of a wrong password, recomputed with Perm^-1.
            y = from_mnemonic(case["container"])
            wrong = password_bytes(case["wrongPassword"])
            x, _ = permute(Geometry(3), y, 0, case["pim"],
                           lambda i, salt: reduced_argon2(wrong, salt), False)
            check(to_mnemonic(x) == case["recoveredAs24"], f"case {number}: wrong-password reading")
    print(f"PASS batch: {len(cases)} reduced-cost containers of the browser core recomputed")


def gf_tables():
    exp, log = [0] * 4094, [0] * 2048
    value = 1
    for power in range(2047):
        exp[power] = value
        log[value] = power
        value <<= 1
        if value & 0x800:
            value ^= 0x805
    for power in range(2047, 4094):
        exp[power] = exp[power - 2047]
    return exp, log


EXP, LOG = gf_tables()


def gf_mul(a, b):
    return 0 if a == 0 or b == 0 else EXP[LOG[a] + LOG[b]]


def poly_mul(p, q):
    out = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            out[i + j] ^= gf_mul(a, b)
    return out


def generator(k):
    g = [1]
    for power in range(1, k + 1):
        g = poly_mul(g, [1, EXP[power]])
    return g


def repair_words(container, k):
    # m(x) * x^k mod g(x) by polynomial long division, highest degree first.
    data = [INDEX[w] for w in container.split(" ")] + [0] * k
    g = generator(k)
    for i in range(len(data) - k):
        coefficient = data[i]
        if coefficient:
            for j in range(1, k + 1):
                data[i + j] ^= gf_mul(coefficient, g[j])
    return " ".join(WORDS[v] for v in data[-k:])


def evaluate(codeword, x):
    total = 0
    for c in codeword:
        total = gf_mul(total, x) ^ c
    return total


def command_profiles(spec_root):
    spec_root = Path(spec_root)
    profiles = (spec_root / "vectors/profiles/README.md").read_text()
    spec = (spec_root / "README.md").read_text()
    # Generator polynomials as the specification lists them.
    listed = dict(re.findall(r"g_(\d): ([\d, ]+)\n", spec))
    for k in (2, 4, 6, 8):
        check([int(v) for v in listed[str(k)].split(", ")] == generator(k), f"g_{k} coefficients")
    # Repair words table.
    rows = re.findall(r"^\| (`[^|]*`|`abandon` 23 times, then `art`)\s*\| ([^|]*)\|$", profiles,
                      re.M)
    check(len(rows) == 4, f"repair rows {len(rows)}")
    for label, cards in rows:
        if "23 times" in label:
            container = " ".join(["abandon"] * 23 + ["art"])
        else:
            vector = json.loads((spec_root / label.strip("`")).read_text())
            container = vector["container"]
        expected = [c.strip().strip("`") for c in cards.strip().split(" / ")]
        for k, card in zip((2, 4, 6, 8), expected):
            check(repair_words(container, k) == card, f"repair {label} k={k}")
            codeword = [INDEX[w] for w in (container + " " + card).split(" ")]
            check(all(evaluate(codeword, EXP[j]) == 0 for j in range(1, k + 1)), "codeword")
    # Password check word table.
    eff = (WORKSPACE / "mhfe/vendor/eff-large-wordlist/eff_large_wordlist.txt").read_bytes()
    check(hashlib.sha256(eff).hexdigest() == EFF_SHA256, "EFF list hash")
    eff_words = [line.split("\t")[1] for line in eff.decode().split("\n") if line]
    check(len(eff_words) == 7776, "EFF list size")
    rows = re.findall(r"^\| `([1-6 ]+)`\s*\| (\d+)\s*\| `([^`]+)`\s*\|$", profiles, re.M)
    check(len(rows) == 4, f"check word rows {len(rows)}")
    for rolls, index, password in rows:
        drawn = [sum((int(d) - 1) * 6 ** (4 - p) for p, d in enumerate(r)) for r in rolls.split()]
        c = (1 * drawn[0] + 5 * drawn[1] + 7 * drawn[2] + 11 * drawn[3] + 13 * drawn[4]) % 7776
        check(c == int(index), f"check index {rolls}")
        check(" ".join(eff_words[d] for d in drawn + [c]) == password, f"password {rolls}")
    # Wallet check table: E = 192 zero bits || BE64(counter).
    rows = re.findall(r"^\| (\d+)\s*\| (`TREZOR`|empty string)\s*\| `([0-9a-f]{64})` \|$", profiles,
                      re.M)
    check(len(rows) == 2, f"wallet check rows {len(rows)}")

    def digest(counter, passphrase, with_bits=True):
        entropy = bytes(24) + counter.to_bytes(8, "big")
        mnemonic = unicodedata.normalize("NFKD", to_mnemonic(entropy)).encode()
        salt = b"mnemonic" + unicodedata.normalize("NFKD", passphrase).encode()
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic, salt, 2048, 64)
        bits = be32(256) if with_bits else b""
        return hashlib.sha256(b"MHFE-WALLET-CHECK-SEED-1" + bits + seed).hexdigest()

    for counter, passphrase, expected in rows:
        passphrase = "TREZOR" if passphrase == "`TREZOR`" else ""
        check(digest(int(counter), passphrase) == expected, f"wallet check {counter}")
        check(expected.startswith("0000"), "passes")
    check(digest(76562, "").startswith("ebd07f71"), "negative 76562 empty")
    check(digest(98918, "TREZOR").startswith("8d2b97fb"), "negative 98918 TREZOR")
    check(digest(76562, "TREZOR", False).startswith("f2c9f765"), "negative without BE32(256)")
    check(to_mnemonic(bytes(24) + (98918).to_bytes(8, "big"))
          == " ".join(["abandon"] * 21 + ["absorb", "another", "spoil"]), "98918 words")
    print("PASS profiles: wallet check digests and negatives, 16 repair cards with codeword "
          "property, generator coefficients, 4 check-word passwords")


def eff_list():
    eff = (WORKSPACE / "mhfe/vendor/eff-large-wordlist/eff_large_wordlist.txt").read_bytes()
    check(hashlib.sha256(eff).hexdigest() == EFF_SHA256, "EFF list hash")
    return [line.split("\t")[1] for line in eff.decode().split("\n") if line]


def check_index(drawn):
    return (1 * drawn[0] + 5 * drawn[1] + 7 * drawn[2] + 11 * drawn[3] + 13 * drawn[4]) % 7776


def command_profilecases(path):
    """Recomputes what profiles_probe.mjs recorded from the browser package."""
    data = json.loads(Path(path).read_text())
    repaired = 0
    for case in data["repair"]:
        container, k = case["container"], case["k"]
        check(case["card"] == repair_words(container, k), f"card of {container!r} k={k}")
        outcome = case["outcome"]
        check("value" in outcome, f"repair within 2e+s<=k refused: {case}")
        value = outcome["value"]
        check(value["container"] == container, f"repair result {case}")
        all_words = container.split(" ") + case["card"].split(" ")
        typed = case["written"].split(" ") + case["typedCard"].split(" ")
        n = len(container.split(" "))
        changes = {(c["onCard"], c["position"]): c for c in value["changes"]}
        expected = {(p >= n, p - n + 1 if p >= n else p + 1) for p in case["positions"]}
        check(set(changes) == expected, f"changes listed {sorted(changes)} vs damage {expected}")
        for (on_card, position), change in changes.items():
            index = position - 1 + (n if on_card else 0)
            check(change["word"] == all_words[index], "repaired word")
            read = None if typed[index] == "?" else typed[index]
            check(change["read"] == read, "what was read is shown")
        repaired += 1
    eff = eff_list()
    eff_index = {word: i for i, word in enumerate(eff)}
    reviews = 0
    for case in data["checkWord"]:
        original = case["original"].split(" ")
        drawn = [eff_index[w] for w in original[:5]]
        check(eff[check_index(drawn)] == original[5], "generated check word")
        tokens = case["text"].split(" ")
        value = case["outcome"]["value"]
        gaps = [i for i, t in enumerate(tokens) if t not in eff_index]
        if not gaps and tokens == original:
            check(value["reading"] == "fits" and value["repairs"] == [], f"fits {case['text']}")
        elif len(gaps) == 1:
            check(value["reading"] == "restorable", f"restorable {case['text']}")
            check(value["repairs"] == [{"position": gaps[0] + 1, "word": original[gaps[0]],
                                        "typed": None}], f"restored word {case}")
        else:
            check(value["reading"] == "mismatch" and len(value["repairs"]) == 6, f"mismatch {case}")
            for repair in value["repairs"]:
                fixed = list(tokens)
                fixed[repair["position"] - 1] = repair["word"]
                indexes = [eff_index[w] for w in fixed]
                check(check_index(indexes[:5]) == indexes[5], f"repair fits {repair}")
                check(repair["typed"] == tokens[repair["position"] - 1], "typed word shown")
            check(any(r["word"] == original[r["position"] - 1] and tokens[r["position"] - 1]
                      != original[r["position"] - 1] for r in value["repairs"]),
                  "one repair restores the original")
        reviews += 1
    passes = 0
    for case in data["walletCheck"]:
        words = case["phrase"].split(" ")
        outcome = case["outcome"]
        if case["passphrase"] == "":
            check(outcome == {"error": "WALLET_CHECK_NEEDS_PASSPHRASE"}, f"empty passphrase {case}")
            continue
        if len(words) != 24:
            check(outcome == {"error": "INVALID_WORD_COUNT"}, f"length {case}")
            continue
        entropy = from_mnemonic(case["phrase"])
        mnemonic = unicodedata.normalize("NFKD", case["phrase"]).encode()
        salt = b"mnemonic" + unicodedata.normalize("NFKD", case["passphrase"]).encode()
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic, salt, 2048, 64)
        digest = hashlib.sha256(b"MHFE-WALLET-CHECK-SEED-1" + be32(8 * len(entropy)) + seed)
        expected = digest.digest()[:2] == b"\0\0"
        check(outcome == {"value": expected}, f"wallet check {case}")
        passes += expected
    check(passes >= 1, "a passing wallet check case is included")
    print(f"PASS profilecases: {repaired} cards and repairs, {reviews} check-word reviews, "
          f"{len(data['walletCheck'])} wallet checks ({passes} passing) agree with the oracle")


def command_phrases(path):
    total = 0
    for line in Path(path).read_text().splitlines():
        hex_input, result = line.split(" ", 1)
        text = bytes.fromhex(hex_input).decode()
        tokens = text.split()
        resolved = [resolve(t) for t in tokens]
        if len(tokens) not in (12, 15, 18, 21, 24) or None in resolved:
            expected = "err:INVALID_PHRASE"
        elif from_mnemonic(" ".join(resolved)) is None:
            expected = "err:INVALID_PHRASE"
        else:
            expected = "ok:" + " ".join(resolved).encode().hex()
        check(result == expected, f"phrase {text!r}: library {result}, rule {expected}")
        total += 1
    print(f"PASS phrases: {total} typed phrases read as the Reading words rule reads them")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    {
        "vectors": command_vectors,
        "reduced": command_reduced,
        "batch": command_batch,
        "profiles": command_profiles,
        "phrases": command_phrases,
        "profilecases": command_profilecases,
    }[sys.argv[1]](sys.argv[2])
