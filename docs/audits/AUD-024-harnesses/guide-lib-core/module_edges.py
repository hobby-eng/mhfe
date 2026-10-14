#!/usr/bin/env python3
"""AUD-024 guide-lib-core: dependency edges, in non-test library code, that tie the independent
parts of the library (CORE-04: repair words, password tools, wallet checks, encryption core) to the
encryption core or to a front end. Each edge is looked for at the line that makes it. Exits 1 when
any of them is present. Run from the repository root."""
import re, sys, pathlib

def non_test(path):
    lines = pathlib.Path(path).read_text().splitlines()
    for index, line in enumerate(lines):
        if re.match(r'\s*#\[cfg\(test\)\]', line) and index + 1 < len(lines) and 'mod tests' in lines[index + 1]:
            return lines[:index]
    return lines

EDGES = [
    ('src/phrase.rs', r'crate::ContainerFacts::read',
     'phrase -> container: check_container, whose ContainerFacts reaches mhfe, wallet and rehearsal'),
    ('src/container.rs', r'use crate::\{other_detected_lengths',
     'container -> mhfe (the encryption core) and wallet'),
    ('src/memory.rs', r'use crate::engine::\{lock_pages, page_size, unlock_pages\}',
     'memory -> engine: mlock comes from the Argon2 FFI module'),
    ('src/packing.rs', r'crate::phrase::WORD_COUNTS',
     'packing -> phrase, while phrase -> packing'),
    ('src/suite.rs', r'use crate::engine::Argon2Cost',
     'suite -> engine, while engine -> suite (WorkFactor)'),
    ('src/engine/browser.rs', r'crate::wasm_api::js_message',
     'engine -> wasm_api: a library module depends on the browser bindings'),
]
present = 0
for path, pattern, what in EDGES:
    hits = [n for n, line in enumerate(non_test(path), 1) if re.search(pattern, line)]
    if hits:
        present += 1
        print(f'{path}:{hits[0]}: {what}')
users = [str(p) for p in pathlib.Path('src').rglob('*.rs')
         if str(p) not in ('src/phrase.rs', 'src/lib.rs') and re.search(r'\bcheck_container\b', p.read_text())]
if not users:
    print('src/phrase.rs:148: check_container has no caller in src/ (only the re-export at src/lib.rs:88)')
print(f'{present} edge(s) present')
sys.exit(1 if present else 0)
