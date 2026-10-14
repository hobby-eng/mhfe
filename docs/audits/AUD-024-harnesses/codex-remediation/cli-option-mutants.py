"""
Meaningful controls for argument-local help and post-recovery option
use.
"""
import hashlib
import json
import subprocess
from pathlib import Path
paths = [Path('src/suite.rs'), Path('src/bin/mhfe/rekey.rs'), Path('src/bin/mhfe/decrypt.rs')]
baseline = {p: p.read_bytes() for p in paths}
records = []


def run(label, changes, test, marker, expected):
    try:
        for p, (old, new) in changes.items():
            text = baseline[p].decode()
            assert text.count(old) == 1, (p, old)
            p.write_text(text.replace(old, new))
        result = subprocess.run(['cargo', 'test', '--locked', '--bin', 'mhfe', test],
            capture_output=True, timeout=120)
        output = result.stdout + result.stderr
        Path(f'../tmp/aud024/{label}.log').write_bytes(output)
        assert result.returncode == expected, (label, output[-3000:].decode())
        assert marker in output, (label, output[-3000:].decode())
        records.append({'control': label, 'exitCode': result.returncode,
                'marker': marker.decode(),
                'sources': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
                'logSha256': hashlib.sha256(output).hexdigest()})
        print(label, '->', result.returncode)
    finally:
        for p, data in baseline.items():
            p.write_bytes(data)


run('stale-new-pim-help', {paths[0]: ('pub const MAX_PIM: u32 = 1023;',
            'pub const MAX_PIM: u32 = 1022;'),
        paths[1]: ('help = format!("PIM of the new container'
            ', {} (default 0)", settings::pim_range()'
            ')', 'help = "PIM of the new container, 0 to 1'
            '023 (default 0)"')},
    'every_settings_argument_states_its_own_limits', b'rekey --new-pim', 101)
run('ignored-decrypt-passphrase-option',
    {paths[2]: ('let used = self.passphrase_used.given();', 'let used = None;')},
    'an_explicit_no_passphrase_skips_terminal_input_after_recovery', b'FAILED', 101)
run('restored-option-controls', {}, 'every_settings_argument_states_its_own_limits',
    b'test result: ok', 0)
run('restored-passphrase-option', {},
    'an_explicit_no_passphrase_skips_terminal_input_after_recovery', b'test result: ok', 0)
for p, data in baseline.items():
    assert p.read_bytes() == data, p
Path('../tmp/aud024/cli-option-mutants.json').write_text(json.dumps(records, indent=2) + '\n')
print('Both regressions caught; every source byte restored and both positive controls pass.')
