"""Inspect static data without project import, compiler or Argon2 execution."""
import ast
import hashlib
import json
from pathlib import Path
import re
import sys
if sys.flags.optimize:
    raise SystemExit('Run audit harnesses without Python optimization')
ROOT = Path.cwd()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RustData:
    """Parse the closed literal grammar of the published-round generator."""
    token = re.compile(
        r'\s*(b?"(?:\\.|[^"\\])*"|'
        r'[A-Za-z_][A-Za-z_0-9]*|[0-9]+|[][{}():,&])'
    )

    def __init__(self, text):
        self.tokens = []
        end = 0
        while end < len(text):
            if not text[end:].strip():
                break
            match = self.token.match(text, end)
            if match is None:
                raise ValueError(
                    f'unparsed bytes at {end}: {text[end:end + 30]!r}'
                )
            self.tokens.append(match[1])
            end = match.end()
        self.offset = 0

    def take(self, expected=None):
        result = self.tokens[self.offset]
        self.offset += 1
        if expected is not None and result != expected:
            raise ValueError((result, expected))
        return result

    def parse(self):
        token = self.take()
        if token == '&':
            return self.parse()
        if token == '[':
            values = []
            while self.tokens[self.offset] != ']':
                values.append(self.parse())
                if self.tokens[self.offset] != ']':
                    self.take(',')
            self.take(']')
            return values
        if token == 'hex':
            self.take('(')
            value = self.parse()
            self.take(')')
            return bytes.fromhex(value)
        if token in ('true', 'false'):
            return token == 'true'
        if token.startswith(('"', 'b"')):
            value = re.sub(
                r'\\u\{([0-9a-fA-F]+)\}',
                lambda m: chr(int(m[1], 16)), token,
            )
            return ast.literal_eval(value)
        if token.isdecimal():
            return int(token)
        constructors = (
            'PublishedVector', 'PublishedReading', 'PublishedRound',
        )
        if token not in constructors:
            raise ValueError(f'unknown literal constructor {token}')
        self.take('{')
        result = {}
        while self.tokens[self.offset] != '}':
            key = self.take()
            if key in result:
                raise ValueError('duplicate field ' + key)
            self.take(':')
            result[key] = self.parse()
            if self.tokens[self.offset] != '}':
                self.take(',')
        self.take('}')
        return result


def require_equal(actual, expected, place):
    if actual != expected:
        raise ValueError(f'literal/fixture mismatch at {place}')


published_path = ROOT / 'src/mhfe/published_rounds.rs'
source = published_path.read_text()
body = source.split('= ', 1)[1].rstrip().removesuffix(';')
parser = RustData(body)
rows = parser.parse()
require_equal(parser.offset, len(parser.tokens), 'full token consumption')
require_equal(len(rows), 27, 'vector count')
require_equal(len({row['name'] for row in rows}), 27, 'distinct vector count')
bindings = []
for row in rows:
    expected_keys = {
        'name', 'same_length', 'startup', 'phrase', 'password',
        'password_nfkd', 'pim', 'memory_level', 'container',
        'recovery', 'rounds',
    }
    require_equal(set(row), expected_keys, row['name'] + ': field set')
    folder = 'suite4-vectors' if row['same_length'] else 'suite3-vectors'
    path = ROOT / 'tests/fixtures' / folder / (row['name'] + '.json')
    fixture = json.loads(path.read_text())
    require_equal(row['name'], fixture['name'], row['name'] + ': name')
    for key in ('phrase', 'password', 'pim', 'memory_level'):
        require_equal(
            row[key], fixture['inputs'][key], row['name'] + ': ' + key,
        )
    require_equal(
        row['password_nfkd'].hex(),
        fixture['inputs']['password_nfkd_utf8_hex'],
        row['name'] + ': password bytes',
    )
    require_equal(
        row['container'], fixture['container'], row['name'] + ': container',
    )
    recovery = fixture['recovery']
    if isinstance(recovery, dict):
        recovery = [recovery]
    expected_recovery = [
        {k: r[k] for k in ('words', 'verified', 'phrase')} for r in recovery
    ]
    require_equal(
        row['recovery'], expected_recovery,
        row['name'] + ': all recovery fields/order',
    )
    require_equal(len(row['rounds']), 12, row['name'] + ': round count')
    require_equal(
        len(fixture['encryption']['rounds']), 12,
        row['name'] + ': fixture round count',
    )
    for index, (round_row, round_fixture) in enumerate(zip(
        row['rounds'], fixture['encryption']['rounds'],
    )):
        require_equal(
            set(round_row), {'salt', 'key'}, row['name'] + ': round fields',
        )
        require_equal(len(round_row['salt']), 16, row['name'] + ': salt width')
        require_equal(len(round_row['key']), 32, row['name'] + ': key width')
        require_equal(
            round_row['salt'].hex(), round_fixture['salt_hex'],
            row['name'] + ': salt ' + str(index),
        )
        require_equal(
            round_row['key'].hex(), round_fixture['argon2_key_hex'],
            row['name'] + ': key ' + str(index),
        )
    require_equal(
        len(fixture['decryption']['rounds']), 12,
        row['name'] + ': decrypt round count',
    )
    salts = {r['salt'].hex() for r in row['rounds']}
    if any(
        r['salt_hex'] not in salts for r in fixture['decryption']['rounds']
    ):
        raise ValueError(row['name'] + ': unexpected decryption salt')
    bindings.append({
        'name': row['name'], 'fixture': str(path.relative_to(ROOT)),
        'fixtureSha256': sha(path), 'startup': row['startup'],
        'sameLength': row['same_length'],
        'recoveryReadings': len(row['recovery']),
        'roundCount': len(row['rounds']),
    })
fixture_set = {
    str(p.relative_to(ROOT))
    for folder in ('suite3-vectors', 'suite4-vectors')
    for p in (ROOT / 'tests/fixtures' / folder).glob('*.json')
    if p.name not in ('negative-vectors.json', 'independent-verification.json')
}
positive_set = set()
for p in fixture_set:
    if 'encryption' in json.loads((ROOT / p).read_text()):
        positive_set.add(p)
require_equal(
    {r['fixture'] for r in bindings}, positive_set,
    'all positive fixtures exactly once',
)
require_equal(sum((r['startup'] for r in bindings)), 10, 'startup count')
widths_path = ROOT / 'src/bin/mhfe/cell_widths.rs'
widths = widths_path.read_text()
header, body = widths.split('pub(crate) const RUNS:', 1)
body = body.split('= [', 1)[1].rsplit('];', 1)[0]
pattern = re.compile('\\s*\\((0x[0-9A-F]+), (0x[0-9A-F]+), ([02])\\),')
position = 0
runs = []
while position < len(body):
    if not body[position:].strip():
        break
    match = pattern.match(body, position)
    if match is None:
        raise ValueError('unparsed cell-width table content')
    runs.append((int(match[1], 16), int(match[2], 16), int(match[3])))
    position = match.end()
require_equal(len(runs), 502, 'cell-width interval count')
previous = None
for first, last, cells in runs:
    if not 0 <= first <= last <= 1114111 or (first <= 57343 and last >= 55296):
        raise ValueError('non-scalar cell-width run')
    if previous and (
        previous[1] >= first
        or (previous[1] + 1 == first and previous[2] == cells)
    ):
        raise ValueError('unsorted/overlapping/non-maximal cell-width runs')
    previous = (first, last, cells)
report = {
    'method': (
        'Standalone Python standard-library closed literal parser. '
        'All PUBLISHED source tokens consumed and every protocol '
        'literal field '
        'compared to every positive JSON fixture. All cell-width interval '
        'rows consumed and structurally checked. No project code, build, '
        'test, Argon2, Unicode database regeneration, external vectors '
        'or cryptographic oracle executed.'
    ),
    'publishedTable': {
        'path': str(published_path.relative_to(ROOT)),
        'sha256': sha(published_path), 'vectorCount': len(rows),
        'roundCount': sum(len(r['rounds']) for r in rows),
        'fixtureBindings': bindings,
        'result': 'all protocol fields/order match 27 fixtures',
        'startupSelectionLimit': (
            'Startup flags are parsed and counted (10); the exact per-vector '
            'startup set has no counterpart in the protocol fixtures and '
            'is not independently checked by this parser.'
        ),
    },
    'cellWidths': {
        'path': str(widths_path.relative_to(ROOT)),
        'sha256': sha(widths_path), 'runs': len(runs),
        'zeroCellRuns': sum(c == 0 for _, _, c in runs),
        'twoCellRuns': sum(c == 2 for _, _, c in runs),
        'result': (
            'all 502 intervals parse; sorted, disjoint, maximal, scalar, '
            'widths 0 or 2'
        ),
        'limitation': (
            'Unicode 17 semantic character-property equivalence and terminal '
            'behavior not recomputed; generator source/provenance '
            'inspected statically.'
        ),
    },
}
report['summary'] = {
    'publishedVectors': len(rows),
    'literalRounds': sum(len(r['rounds']) for r in rows),
    'startupVectors': sum(r['startup'] for r in bindings),
    'cellWidthRuns': len(runs),
    'result': 'static literal/fixture comparison and table structure match',
}
print(json.dumps(report, indent=2))
