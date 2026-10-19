"""Print Git-visible file hashes and lexical Rust declarations for AUD-026.

Run from the MHFE repository root. This is read-only and uses no external
Python packages. Declarations are candidates, not a semantic public API count.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    """Inventory present tracked/nonignored files, excluding ignored output."""
    root = Path.cwd()
    names = subprocess.check_output(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard'],
        cwd=root, text=True,
    ).splitlines()
    files = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in sorted(set(names)) if (root / name).is_file()
    }
    source = {
        name: digest for name, digest in files.items()
        if not name.startswith('docs/audits/')
    }
    listing = ''.join(
        f'{digest}  {name}\n' for name, digest in source.items()
    )
    declarations = []
    for name in source:
        if not name.startswith('src/') or not name.endswith('.rs'):
            continue
        lines = (root / name).read_text().splitlines()
        for number, line in enumerate(lines, 1):
            if re.search('\\bpub\\s+(?:const\\s+|async\\s+)?fn\\s+', line):
                declarations.append({
                    'path': name, 'line': number,
                    'declaration': line.strip(),
                })
    print(json.dumps({
        'files': files, 'fileCount': len(files),
        'nonAuditFileCount': len(source),
        'sourceFingerprint': hashlib.sha256(listing.encode()).hexdigest(),
        'lexicalDeclarationCandidates': declarations,
        'limit': 'Not a semantic Rust parser or an execution-coverage proof.',
    }, indent=2))


if __name__ == '__main__':
    main()
