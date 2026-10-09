"""AUD-017 R1 probe: the length rules of recovery and the 16-bit source check.

Builds an oracle from the bullet list of mhfe_spec README.md "Recovering a mnemonic" (the
uncommitted revision of 2026-10-09) and compares it with `stated_recovery` of
scripts/independent-suite3.py, extracted by AST without its Argon2 or Unicode dependencies, on
states with zero, one and two passing short layouts and every stated length. It then checks the
recorded `stated-24-words` and `selected-24-words` negative cases against the oracle on the state
of zero-12 (the right password recovers X = pack(E)), and the published wallet-check fixtures and
the spec's digest prefix 0f9e2012 with hashlib alone. No Argon2. Public data only.

Exit 1 if any comparison that should agree does not; 0 otherwise.
"""

import ast
import hashlib
import json
import os
import sys
import unicodedata

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../.."))
SCRIPT = os.path.join(ROOT, "scripts/independent-suite3.py")
NEGATIVE = os.path.join(ROOT, "tests/fixtures/suite3-vectors/negative-cases.json")
os.environ.setdefault("CARGO_HOME", os.path.join(os.path.dirname(ROOT), "workingspace/cargo"))

WANTED = {"english_wordlist", "phrase_to_entropy", "entropy_to_phrase", "matching_short_lengths",
          "detected_recovery", "stated_recovery", "read_as", "pack"}
tree = ast.parse(open(SCRIPT, encoding="utf-8").read())
body = []
for node in tree.body:
    if isinstance(node, ast.FunctionDef) and node.name in WANTED:
        body.append(node)
    elif isinstance(node, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id in {"SHORT_LENGTHS", "STATED_READING_ONLY", "WORDS"}
        for t in node.targets):
        body.append(node)
ns = {}
import glob, re  # noqa: E401 (used by the extracted functions)
ns.update(hashlib=hashlib, os=os, glob=glob, re=re)
exec(compile(ast.Module(body=body, type_ignores=[]), SCRIPT, "exec"), ns)

SHORT = {12: 16, 15: 20, 18: 24, 21: 28}


def matches(x):
    return [w for w, n in SHORT.items() if hashlib.sha256(x[:n]).digest()[: 32 - n] == x[n:]]


def oracle(x, stated):
    """Spec bullets: lengths as (words, verified) in order, or None for no reading."""
    m = matches(x)
    every = [(w, True) for w in m] + [(24, False)]
    if stated == 0:
        return [(m[0], True)] if len(m) == 1 else every
    if stated in m:
        return [(stated, True)]
    if stated == 24:
        return every
    # A short length stated that does not match.
    if not m:
        return None
    return [(m[0], True)] if len(m) == 1 else every


def pack(e):
    return e + hashlib.sha256(e).digest()[: 32 - len(e)]


states = {
    "zero-12": pack(bytes(16)), "zero-15": pack(bytes(20)), "zero-18": pack(bytes(24)),
    "zero-21": pack(bytes(28)), "zero-24": bytes(32), "random": hashlib.sha256(b"r1").digest(),
    "amb-12-21": bytes.fromhex("4d48464520616d62000000004dda455a85b22f09e43e0ae5de9322dce19210ad"),
    "amb-15-21": bytes.fromhex("4d48464520616d626967756f00000000d7215b3cc350c32cc955fd4e3e272edf"),
    "amb-18-21": bytes.fromhex("4d48464520616d626967756f7573207400000000643a0b3e565fd3c1659f6749"),
}
failures = []
for name, x in states.items():
    for stated in (0, 12, 15, 18, 21, 24):
        got = ns["stated_recovery"](x, stated, "probe")
        got = None if got is None else [(w, v) for w, v, _ in got]
        want = oracle(x, stated)
        status = "ok" if got == want else "DIFFERS"
        print(f"{name:10} stated={stated:2} matches={matches(x)} script={got} spec={want} {status}")
        if got != want:
            failures.append((name, stated))
        if got:
            for w, v, phrase in ns["stated_recovery"](x, stated, "probe"):
                if phrase != ns["entropy_to_phrase"](x[: SHORT.get(w, 32)]):
                    failures.append((name, stated, "phrase"))

# The recorded negative cases on zero-12's state.
x = states["zero-12"]
for case in json.load(open(NEGATIVE)):
    if case["words"] != 24 or case["container"] is None:
        continue
    recorded = [(r["words"], r["verified"]) for r in case["recovery"]]
    phrases = [r["phrase"] for r in case["recovery"]]
    want = oracle(x, 24)
    full = [ns["entropy_to_phrase"](x[: SHORT.get(w, 32)]) for w, _ in want]
    agrees = recorded == want and phrases == full
    print(f"negative {case['name']}: recorded={recorded} spec={want} agrees={agrees}")
    if case["name"] == "stated-24-words" and not agrees:
        failures.append(("stated-24-words",))
    if case["name"] == "selected-24-words":
        print("  selected-24-words is the documented historical record (partial on purpose):",
              recorded == [(24, False)] and phrases[0] == full[-1])


def check_digest(entropy, passphrase):
    phrase = ns["entropy_to_phrase"](entropy)
    seed = hashlib.pbkdf2_hmac("sha512", unicodedata.normalize("NFKD", phrase).encode(),
                               b"mnemonic" + unicodedata.normalize("NFKD", passphrase).encode(), 2048)
    return hashlib.sha256(b"MHFE-WALLET-CHECK-SEED-1" + (len(entropy) * 8).to_bytes(4, "big") + seed).digest()


t = check_digest(x, "")
print("24-word reading of zero-12, empty passphrase: T starts", t[:4].hex(), "passes:", t[:2] == b"\0\0")
if t[:4].hex() != "0f9e2012":
    failures.append(("digest-prefix",))
for counter, passphrase, passes in ((76_562, "TREZOR", True), (76_561, "TREZOR", False),
                                    (98_918, "", True), (76_562, "trezor", False)):
    e = bytes(24) + counter.to_bytes(8, "big")
    ok = (check_digest(e, passphrase)[:2] == b"\0\0") == passes
    print(f"wallet check counter={counter} passphrase={passphrase!r} expected pass={passes} ok={ok}")
    if not ok:
        failures.append(("wallet-check", counter))

print("failures:", failures)
sys.exit(1 if failures else 0)
