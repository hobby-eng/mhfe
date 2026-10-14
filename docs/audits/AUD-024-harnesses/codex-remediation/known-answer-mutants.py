"""
In-place faults with exact restoration; no project copy and no full-cost
Argon2.
"""
import datetime
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
F = 'src/wallet.rs'
COINS = 'wallet::known_answers::address_search::tests::a_search_description_covers'
cases = [('bitcoin-root', F, 'Self::Bitcoin => &[0],', 'Self::Bitcoin => &[999],', COINS),
    ('ethereum-injective-root', F, 'Self::Ethereum | Self::Injective => &[60],',
        'Self::Ethereum | Self::Injective => &[999],', COINS), ('xrp-root', F,
        'Self::Xrp => &[144],', 'Self::Xrp => &[143],', COINS), ('tron-root', F,
        'Self::Tron => &[195],', 'Self::Tron => &[194],', COINS), ('zcash-root', F,
        'Self::Zcash => &[133],', 'Self::Zcash => &[132],', COINS),
    ('dogecoin-root', F, 'Self::Dogecoin => &[3],',
        'Self::Dogecoin => &[4],', COINS), ('cash-primary-root', F,
        'Self::BitcoinCash => &[145, 0],',
        'Self::BitcoinCash => &[144, 0],', COINS),
    ('cash-secondary-root', F,
        'Self::BitcoinCash => &[145, 0],',
        'Self::BitcoinCash => &[145, 1],', COINS),
    ('litecoin-root', F,
        'Self::Litecoin => &[2],',
        'Self::Litecoin => &[3],', COINS),
    ('classic-primary-root', F,
        'Self::EthereumClassic => &[61, 60],',
        'Self::EthereumClassic => &[62, 60],',
        COINS), ('classic-secondary-root',
        F, 'Self::EthereumClassic => &[61, 60],',
        'Self::EthereumClassic => &[61, 59],',
        COINS), ('cosmos-root',
        F, 'Self::Cosmos => &[118],',
        'Self::Cosmos => &[119],',
        COINS), ('dash-root',
        F, 'Self::Dash => &[5],',
        'Self::Dash => &[6],',
        COINS), ('standard-root-loop',
        F, 'for root in address.search_roots() {',
        'for root in address.search_roots().into_'
        'iter().take(1) {',
        'wallet::known_answers::addresses::tests:'
        ':the_address_check_passes'),
    ('wallet-evidence', 'src/rehearsal.rs',
        'other => Some(detection.source_check(oth'
        'er.passphrase().unwrap_or(""))?),',
        'other => Some(!detection.source_check(ot'
        'her.passphrase().unwrap_or(""))?),',
        'rehearsal::known_answers'),
    ('passed-check-list', 'src/rehearsal.rs',
        '(Some(words), _) => passed.push(PassedCh'
        'eck::BuiltInCheck(words)),',
        '(Some(_), _) => {}',
        'rehearsal::known_answers'),
    ('old-container-keep',
        'src/operation.rs',
        'items.extend(changed_settings(old_work));',
        'let _ = old_work;',
        'operation::known_answers'),
    ('reference-replacement',
        'src/rekey.rs', 'if !self.by_owner {',
        'if !self.by_owner && passphrase.len() =='
        ' usize::MAX {', 'rekey::known_answers'),
    ('target-comparison', 'src/rekey/known_answers.rs',
        'sealed.container() == to.container,',
        'true,', 'rekey::known_answers'),
    ('all-refusals', 'src/rekey/known_answers.rs',
        "fn run(&self, vectors: &'static [Publish"
        'edVector]) -> Result<(), String> {',
        "fn run(&self, vectors: &'static [Publish"
        'edVector]) -> Result<(), String> {\n     '
        '   if !vectors.is_empty() { return Ok(()'
        '); }', 'rekey::known_answers'),
    ('repeat-confirmation',
        'src/rekey/known_answers.rs',
        'fn confirmed_again(&self) -> Result<(), '
        'String> {', 'fn confirmed_again(&self) -> Result<(), '
        'String> {\n        if !self.vectors.is_em'
        'pty() { return Ok(()); }', 'rekey::known_answers')]
source = Path(F).read_text()
old = 'CHAINS.map(|chain| chain | HARDENED)'
assert source.count(old) == 1
cases.append((
    'dip17-runtime-chains', F,
    source[
        source.rindex('    let chains = if address.hardened_chains()'):
        source.index('    for root in address.search_roots()',
                     source.rindex('    let chains = if address.hardened_chains()'))
    ],
    source[
        source.rindex('    let chains = if address.hardened_chains()'):
        source.index('    for root in address.search_roots()',
                     source.rindex('    let chains = if address.hardened_chains()'))
    ].replace(old, 'CHAINS'),
    'wallet::known_answers::addresses::tests::the_address_check_passes',
))
paths = {name: Path(name).read_bytes() for _, name, *_ in cases}
out = Path('docs/audits/AUD-024-evidence/codex-known-answer-mutants-final')
out.mkdir()
records = []
try:
    for label, name, old, new, target in cases:
        baseline = paths[name]
        source = baseline.decode()
        assert source.count(old) == 1, (label, source.count(old))
        changed = source.replace(old, new).encode()
        Path(name).write_bytes(changed)
        command = ['cargo', 'test', '--locked', '--lib', target, '--', '--test-threads=1']
        start = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result = subprocess.run(command, capture_output=True, env={**os.environ,
                'CARGO_BUILD_JOBS': '1'}, timeout=180)
        log = result.stdout + result.stderr
        (out / (label + '.log')).write_bytes(log)
        assert (
            result.returncode == 101 and b'test result: FAILED' in log
            and b'error[E' not in log
        ), (label, log.decode()[-4000:])
        record = {'label': label, 'file': name, 'command': command, 'startedUtc': start,
            'endedUtc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'sourceSha256': hashlib.sha256(baseline).hexdigest(),
            'mutatedSha256': hashlib.sha256(changed).hexdigest(),
            'logSha256': hashlib.sha256(log).hexdigest(),
            'exitCode': result.returncode}
        records.append(record)
        print('Caught', label, 'by', target, flush=True)
        Path(name).write_bytes(baseline)
finally:
    for name, baseline in paths.items():
        Path(name).write_bytes(baseline)
    (out / 'manifest.json').write_text(json.dumps(records, indent=2) + '\n')
for name, baseline in paths.items():
    assert Path(name).read_bytes() == baseline
print(len(records), 'faults caught; all exact source bytes restored.', flush=True)
