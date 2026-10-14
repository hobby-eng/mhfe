#!/usr/bin/env python3
"""AUD-024 guide-lib-core: values and messages written more than once in the library (CORE-10),
which the copy gate (scripts/verify-no-copies.mjs, runs of 50 tokens) does not report. Each entry
is a literal and where it is written, split into non-test code and #[cfg(test)] modules (a file
under src/word_wishes/statistics.rs or src/test_support.rs counts as test code). The generated
src/mhfe/published_rounds.rs is left out. Exits 1 when an entry is written more than once.
Run from the repository root."""
import re, sys, pathlib

def split(path):
    lines = path.read_text().splitlines()
    whole_test = path.name in ('statistics.rs', 'test_support.rs')
    for index, line in enumerate(lines):
        if re.match(r'\s*#\[cfg\((all\()?test', line) and index + 1 < len(lines) and re.search(r'\bmod tests\b', lines[index + 1]):
            return ([] if whole_test else list(enumerate(lines[:index], 1)), list(enumerate(lines[index:], index + 1)))
    return ([], list(enumerate(lines, 1))) if whole_test else (list(enumerate(lines, 1)), [])

ENTRIES = [
    ('the Unicode password of the published vectors', r'Caf\\u\{[eE]9\} \\u\{[fF][bB]01\}'),
    ('its bytes after NFKD', r'43616665cc81206669205041cc8a3120f09f949020d0b8cc86'),
    ('the test password', r'"public test password"'),
    ('the message "of another suite"', r'"the built-in cases are of another suite"'),
    ('the message "a built-in vector is missing"', r'"a built-in vector is missing"'),
    ('the EFF list digest', r'addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e'),
    ('the Argon2id tag at 1 MiB', r'e0e8eba33f1404a83c911a324d9b49db83dae755f2bdfb4b63043ca5b7125df2'),
    ('check word vector 3', r'"jovial trailing chokehold pavilion cresting ninth"'),
    ('repair card of zero-12, 8 words', r'"appear include vicious move uphold tiger song satoshi"'),
    ('repair card of zero-12, 4 words', r'"shaft pupil patient jewel"'),
    ('the zero-12 phrase', r'"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"'),
    ('a refused byte of the unbiased draw', r'228u?8?, 5\]'),
    ('the fingerprint of the zero-12 phrase', r'0x73, 0xc5, 0xda, 0x0a'),
]
files = sorted(p for p in pathlib.Path('src').rglob('*.rs') if p.name != 'published_rounds.rs' and 'bin' not in p.parts)
copied = 0
for name, pattern in ENTRIES:
    code, tests = [], []
    for path in files:
        main, test = split(path)
        code += [f'{path}:{n}' for n, line in main if re.search(pattern, line)]
        tests += [f'{path}:{n}' for n, line in test if re.search(pattern, line)]
    if len(code) + len(tests) > 1:
        copied += 1
        print(f'{name}: {len(code)} in code, {len(tests)} in tests')
        for place in code:
            print(f'  code  {place}')
        for place in tests:
            print(f'  test  {place}')
print(f'{copied} value(s) or message(s) written more than once')
sys.exit(1 if copied else 0)
