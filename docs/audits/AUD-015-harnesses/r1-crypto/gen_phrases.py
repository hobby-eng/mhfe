#!/usr/bin/env python3
"""AUD-015 R1: typed phrases for the Reading words rule, one hex-encoded UTF-8 line each.

Every word of the English list, abbreviated to every prefix length from one letter to the whole
word, in upper, lower and mixed case, at a random position of a valid phrase of every length,
with spaces, tabs and line breaks between words; plus a few hand-picked cases. Deterministic: a
fixed linear congruential generator. The phrases are public test data, never wallets.
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oracle import WORDS, to_mnemonic  # noqa: E402

state = 0x2545F491


def next_below(bound):
    global state
    state = (state * 1664525 + 1013904223) % 2**32
    return state % bound


def entropy(length):
    return bytes(next_below(256) for _ in range(length))


def case_variant(token, kind):
    if kind == 0:
        return token
    if kind == 1:
        return token.upper()
    return "".join(c.upper() if i % 2 else c for i, c in enumerate(token))


separators = [" ", "  ", "\t", "\n", " \t "]


def typed(phrase):
    text = phrase[0]
    for token in phrase[1:]:
        text += separators[next_below(len(separators))] + token
    if next_below(4) == 0:
        text = "  " + text + "\n"
    return text


lines = []
for number, word in enumerate(WORDS):
    for cut in range(1, len(word) + 1):
        words = 3 * (4 + next_below(5))  # 12, 15, 18, 21 or 24
        length = words // 3 * 4
        # (a) `word` itself as the first word: its number in the first 11 bits of the entropy.
        raw = int.from_bytes(entropy(length), "big") & ((1 << (8 * length - 11)) - 1)
        raw |= number << (8 * length - 11)
        phrase = to_mnemonic(raw.to_bytes(length, "big")).split(" ")
        assert phrase[0] == word
        phrase[0] = case_variant(word[:cut], next_below(3))
        lines.append(typed(phrase))
        # (b) the word at a random place of another phrase, cut to as many letters.
        phrase = to_mnemonic(entropy(length)).split(" ")
        position = next_below(words)
        phrase[position] = case_variant(phrase[position][:cut], next_below(3))
        lines.append(typed(phrase))
# Hand-picked: the BIP39 zero phrases, a wrong length, an unknown word, an ambiguous prefix.
zero12 = " ".join(["abandon"] * 11 + ["about"])
lines += [zero12, "aban " * 11 + "abou", zero12 + " abandon", zero12.replace("about", "abo"),
          zero12.replace("about", "zzzz"), "ACT " * 11 + "act", " ".join(["abandon"] * 12)]
for text in lines:
    print(text.encode().hex())
print(f"{len(lines)} phrases, sha256 of list "
      f"{hashlib.sha256(chr(10).join(lines).encode()).hexdigest()}", file=sys.stderr)
