#!/usr/bin/env python3
"""AUD-024 guide-lib-core: public items of the library (items of public modules, crate-root
re-exports, public fields) that no code outside the library uses: neither the command-line tool
(src/bin, a crate of its own) nor the integration tests (tests/). CORE-11: visible only when a
caller needs them; RUST-06: pub is for the library's API. Library users (including the bindings
in src/wasm_api) are listed, since pub(crate) serves them. Exits 1 when one has no outside user."""
import re, sys, pathlib

ITEMS = [
    ('src/mhfe.rs', 'into_phrase', r'\binto_phrase\b'),
    ('src/new_password.rs', 'NewPassword::recipe', r'\.recipe\(\)'),
    ('src/memory.rs', 'LockProbe::of', r'LockProbe::of\b'),
    ('src/memory.rs', 'LockedText::from_locked', r'\bfrom_locked\b'),
    ('src/memory.rs', 'LockedPages', r'\bLockedPages\b'),
    ('src/operation.rs', 'Sealed::container_words', r'\.container_words\(\)'),
    ('src/repair.rs', 'card_text', r'\bcard_text\b'),
    ('src/mhfe.rs', 'NewContainer::words (pub field)', r'NewContainer|encrypt_unchecked'),
    ('src/phrase.rs', 'check_phrase (crate-root re-export)', r'\bcheck_phrase\b'),
    ('src/phrase.rs', 'read_phrase (crate-root re-export)', r'\bread_phrase\b'),
    ('src/phrase.rs', 'check_container (crate-root re-export)', r'\bcheck_container\b'),
    ('src/mhfe.rs', 'other_detected_lengths (crate-root re-export)', r'\bother_detected_lengths\b'),
]
corpus = {str(p): p.read_text() for p in list(pathlib.Path('src').rglob('*.rs')) + list(pathlib.Path('tests').rglob('*.rs'))}
unused = 0
for home, name, pattern in ITEMS:
    module = home[:-3]
    outside = [f for f, text in corpus.items()
               if f != home and not f.startswith(module + '/') and f != 'src/lib.rs' and re.search(pattern, text)]
    crate_outside = [f for f in outside if not f.startswith('src/bin/') and not f.startswith('tests/')]
    external = [f for f in outside if f.startswith('src/bin/') or f.startswith('tests/')]
    if not external:
        unused += 1
        inside = ', '.join(sorted(crate_outside)) or 'none'
        print(f'{home}: {name}: no user in the command-line tool or tests/; other library users: {inside}')
print(f'{unused} public item(s) without an outside user')
sys.exit(1 if unused else 0)
