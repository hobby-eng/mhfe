from pathlib import Path
import hashlib
import json
import subprocess
import sys
if sys.flags.optimize:
    raise SystemExit('Run audit harnesses without Python optimization')
root = Path.cwd()
spec = root.parent / 'mhfe_spec'
listed = subprocess.check_output(
    ['git', 'ls-files'], cwd=spec, text=True,
).splitlines()
records = []
for relative in listed:
    p = Path(relative)
    is_suite = any(
        relative.startswith('vectors/' + s + '/')
        for s in ['suite3', 'suite4']
    )
    if p.suffix != '.json' or not is_suite:
        continue
    suite = p.parts[1]
    folder = 'suite3-vectors' if suite == 'suite3' else 'suite4-vectors'
    local = root / 'tests/fixtures' / folder / p.name
    if suite == 'suite3' and p.name == 'validation-cases.json':
        local = root / 'tests/fixtures/validation-cases.json'
    a = (spec / p).read_bytes()
    b = local.read_bytes()
    assert a == b, (relative, str(local))
    json.loads(a)
    records.append({
        'specification': relative,
        'implementation': str(local.relative_to(root)),
        'sha256': hashlib.sha256(a).hexdigest(),
        'byteIdentical': True,
    })
assert len(records) == 31, len(records)
for suite in ['suite3', 'suite4']:
    folder = spec / 'vectors' / suite
    for row in (folder / 'SHA256SUMS').read_text().splitlines():
        if not row.strip():
            continue
        h, n = row.split(maxsplit=1)
        n = n.lstrip('*')
        assert hashlib.sha256((folder / n).read_bytes()).hexdigest() == h, n
print(json.dumps({
    'specificationCommit': subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=spec, text=True,
    ).strip(),
    'specificationWorkingTree': subprocess.check_output(
        ['git', 'status', '--porcelain=v1'], cwd=spec, text=True,
    ),
    'fixtureCount': len(records),
    'fixtures': records,
    'scope': (
        'Exact fixture consistency and published checksum comparison, '
        'not a full-cost crypto replay or proof audit.'
    ),
}, indent=2))
