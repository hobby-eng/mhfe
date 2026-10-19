"""Independent fixture/lock validation using Python stdlib tomllib; no KDF execution."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import re
import resource
import sys
import tomllib

resource.setrlimit(resource.RLIMIT_AS, (64 * 1024 * 1024, 64 * 1024 * 1024))
if not __debug__:
    raise SystemExit('This assertion-based audit checker refuses Python optimization')
if len(sys.argv) != 2:
    raise SystemExit('usage: python3 structured-data.py AUD-029-report.json')
ROOT = Path.cwd().resolve()
STARTED = datetime.now(timezone.utc).isoformat()
SHA = lambda value: hashlib.sha256(value).hexdigest()
FILE_SHA = lambda path: SHA(path.read_bytes())
baseline_path = Path(sys.argv[1])
report = json.loads(baseline_path.read_text())
if report.get('auditId') != 'AUD-029':
    raise ValueError('Expected the published AUD029 companion')
baseline = {
    'sourceFiles': {row['path']: row['sha256'] for row in report['scope']['sourceFileInventory']},
    'sourceFingerprint': report['snapshot']['sourceFingerprint'],
}
# Only the data inputs used below must retain their reviewed identities. Later source-code
# remediation does not change those fixtures; this tool does not re-audit that changed code.
expected = {
    name: digest for name, digest in baseline['sourceFiles'].items()
    if name == 'Cargo.lock' or (
        name.startswith('tests/fixtures/') and (name.endswith('.json') or name.endswith('/SHA256SUMS'))
    )
}
before = {name: FILE_SHA(ROOT / name) for name in expected}
assert before == expected


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON object key')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('Non-finite JSON token')


def strict_json(text):
    return json.loads(text, object_pairs_hook=unique_object,
                      parse_constant=reject_constant)


def hex_fields(value, location=''):
    count = 0
    if isinstance(value, dict):
        for key, entry in value.items():
            if key.endswith('_hex'):
                values = [entry] if isinstance(entry, str) else entry
                assert isinstance(values, list), (location, key)
                for token in values:
                    assert isinstance(token, str), (location, key)
                    assert re.fullmatch(r'(?:[0-9a-f]{2})*', token), (location, key)
                    count += 1
            count += hex_fields(entry, location + '/' + key)
    elif isinstance(value, list):
        for index, entry in enumerate(value):
            count += hex_fields(entry, location + '/' + str(index))
    return count


controls = {}
for name, value in [('duplicateKey', '{"x":1,"x":2}'),
                    ('nonFiniteNumber', '{"x":NaN}')]:
    try:
        strict_json(value)
    except ValueError:
        controls[name] = 'refused as expected'
    else:
        raise AssertionError(name)
try:
    hex_fields({'synthetic_hex': 'aG'})
except AssertionError:
    controls['invalidHex'] = 'refused as expected'
else:
    raise AssertionError('invalidHex')

json_paths = sorted(name for name in expected
                    if name.startswith('tests/fixtures/')
                    and name.endswith('.json'))
assert len(json_paths) == 34
json_rows = []
parsed = {}
positive = []
for name in json_paths:
    value = strict_json((ROOT / name).read_text())
    assert isinstance(value, (dict, list)), name
    fields = hex_fields(value, name)
    row = {'path': name, 'sha256': before[name],
           'method': 'Fresh duplicate-key/non-finite-strict full JSON parse; all nested *_hex strings checked lower-case/even-length; no cryptographic recomputation.',
           'rootType': type(value).__name__, 'hexFieldsChecked': fields,
           'schema': value.get('schema') if isinstance(value, dict) else None, 'result': 'pass'}
    if (isinstance(value, dict) and 'suite_id' in value and 'encryption' in value
            and 'decryption' in value and 'container' in value):
        er = value['encryption']['rounds']
        dr = value['decryption']['rounds']
        assert len(er) == len(dr) == 12, name
        assert [v['round'] for v in er] == list(range(12)), name
        assert [v['round'] for v in dr] == list(reversed(range(12))), name
        row['positiveVectorRounds'] = {'encryption': 12, 'decryption': 12}
        positive.append(name)
    json_rows.append(row)
    parsed[name] = value
assert len(positive) == 27

checksum_rows = []
retained_rows = []
for suite, count in [('suite3-vectors', 18), ('suite4-vectors', 11)]:
    base = 'tests/fixtures/' + suite + '/'
    name = base + 'SHA256SUMS'
    entries = []
    for line in (ROOT / name).read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([^/]+\.json)', line)
        assert match, name
        digest, filename = match.groups()
        assert filename not in [r['name'] for r in entries], filename
        actual = FILE_SHA(ROOT / base / filename)
        assert digest == actual, filename
        entries.append({'name': filename, 'sha256': actual})
    assert len(entries) == count
    checksum_rows.append({'path': name, 'sha256': before[name],
                          'method': 'Every listed digest compared with actual current bytes; strict record shape and unique safe basenames.',
                          'entryCount': len(entries), 'entries': entries,
                          'result': 'pass'})
    retained_name = base + 'independent-verification.json'
    retained = parsed[retained_name]
    recorded = retained['files']
    assert {x['name']: x['sha256'] for x in recorded} == {
        x['name']: x['sha256'] for x in entries}
    checker = ROOT / retained['verifier']['program']
    retained_rows.append({'path': retained_name,
                          'sha256': before[retained_name],
                          'recordedChecker': retained['verifier']['program'],
                          'recordedCheckerSha256': retained['verifier']['sha256'],
                          'currentCheckerSha256': FILE_SHA(checker),
                          'currentCheckerIdentityMatchesHistorical': FILE_SHA(checker) == retained['verifier']['sha256'],
                          'allListedVectorBytesMatch': True,
                          'limit': 'Historical verification receipt, not a new execution or current checker replay.'})

lock_name = 'Cargo.lock'
lock = tomllib.loads((ROOT / lock_name).read_text())
packages = lock['package']
assert len(packages) == 109
keys = [(x['name'], x['version'], x.get('source')) for x in packages]
assert len(keys) == len(set(keys))
registry = [x for x in packages if 'source' in x]
assert len(registry) == 108
for package in registry:
    assert package['source'] == 'registry+https://github.com/rust-lang/crates.io-index'
    assert re.fullmatch(r'[0-9a-f]{64}', package['checksum'])
resolved = 0
for package in packages:
    for dependency in package.get('dependencies', []):
        match = re.fullmatch(r'(\S+)(?: ([0-9][^ ]*))?(?: \(([^)]+)\))?', dependency)
        assert match, dependency
        name, version, source = match.groups()
        matches = [x for x in packages if x['name'] == name
                   and (version is None or x['version'] == version)
                   and (source is None or x.get('source') == source)]
        assert len(matches) == 1, dependency
        resolved += 1
lock_result = {'path': lock_name, 'sha256': before[lock_name],
               'method': 'Fresh whole TOML lock parse; unique name/version/source packages, all registry/checksum shapes and every dependency reference resolved uniquely.',
               'packageCount': 109, 'registryPackageCount': 108,
               'dependencyReferencesResolved': resolved, 'result': 'pass',
               'limit': 'No online advisory lookup, registry archive checksum verification or exhaustive dependency-source audit.'}
after = {name: FILE_SHA(ROOT / name) for name in expected}
assert after == before == expected
ended = datetime.now(timezone.utc).isoformat()
result = {'auditId': 'AUD-029', 'phase': 'portable structured-data replay against the published input identities',
          'startedUtc': STARTED, 'endedUtc': ended,
          'baselineSha256': FILE_SHA(baseline_path),
          'baselineSourceFingerprint': baseline['sourceFingerprint'],
          'inputFileMapMatchesBeforeAndAfter': True,
          'jsonFileCount': len(json_rows), 'positiveVectorCount': len(positive),
          'jsonFiles': json_rows, 'checksumSets': checksum_rows,
          'historicalVerificationBindings': retained_rows,
          'cargoLock': lock_result, 'failureControls': controls,
          'limits': ['Only the37 structured inputs are pinned here; no unchanged473-code-source claim.',
                     'Fresh static/structured data validation only; no project modules imported.',
                     'No KDF, mnemonic/seed/key derivation, independent vector computation, build or test-suite execution.',
                     'This does not recreate lost earlier feb357ae bytes or relabel historical receipt as current execution.',
                     'Supplied round values structurally inspected; cryptographic validity remains supplied literal/retained evidence.']}
print(json.dumps(result, indent=2))
