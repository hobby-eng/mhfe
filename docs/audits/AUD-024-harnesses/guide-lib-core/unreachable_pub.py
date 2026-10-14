#!/usr/bin/env python3
"""AUD-024 guide-lib-core: reads the output of `cargo clippy --lib -- -W unreachable_pub` and lists
the `pub` items that the lint finds unreachable from the crate root in the files of the
guide-lib-core scope (RUST-06: pub is for the library's API), each with its line of code. Exits 1
when there is one."""
import re, sys

SCOPE = re.compile(r'src/(lib|error|memory|operation|feistel|packing|mhfe|suite|engine|password|'
                   r'phrase|detection|container|repair|check_word|new_password|strength|random|eff|'
                   r'word_hints|word_wishes|test_support)(\.rs|/)')
lines = open(sys.argv[1]).read().splitlines()
found = []
for index, line in enumerate(lines):
    if not line.startswith('warning: unreachable `pub`'):
        continue
    for follow in range(index + 1, min(index + 8, len(lines))):
        where = re.search(r'--> (src/[^:]+):(\d+):', lines[follow])
        if where:
            code = next((re.sub(r'^\s*\d+\s*\|\s?', '', l) for l in lines[follow + 1:follow + 4]
                         if re.match(r'^\s*\d+\s*\|', l)), '')
            path, number = where.group(1), int(where.group(2))
            if SCOPE.match(path) and 'published_rounds' not in path:
                found.append((path, number, code.strip()))
            break
for path, number, code in sorted(found):
    print(f'{path}:{number}: {code}')
print(f'{len(found)} unreachable pub item(s) in scope')
sys.exit(1 if found else 0)
