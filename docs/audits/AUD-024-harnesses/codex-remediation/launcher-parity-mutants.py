"""
Prove that every newly covered standalone message/constant drift is
refused.
"""
import hashlib
import subprocess
from pathlib import Path
path = Path('packaging/mhfe-fast-mode.py')
baseline = path.read_bytes()
source = baseline.decode()
cases = [('TITLE = "Fast mode"', 'TITLE = "Different mode"'), ('SHA256_HEX_DIGITS = 64',
        'SHA256_HEX_DIGITS = 65'), ('SUCCESS = 0', 'SUCCESS = 9'), ('INTERNAL_ERROR = 1',
        'INTERNAL_ERROR = 9'), ('INVALID_INPUT = 2', 'INVALID_INPUT = 9'),
    ('There is no readable {}', 'There is no readable changed {}'),
    ('{} names {}, not {}', '{} names changed {}, not {}'), ('Cannot read {}:',
        'Cannot read changed {}:'), ('{} is larger than {} MiB',
        '{} is larger than changed {} MiB'), ('The SHA-256 of {} is {}',
        'The SHA-256 of {} is changed {}'), ('SHA-256 of {} verified',
        'SHA-256 of {} verified changed'), ('Open {} in your browser.',
        'Open changed {} in your browser.'),
    ('Opened {}; if no browser',
        'Opened changed {}; if no browser'),
    ('Fast mode is running.',
        'Fast mode is running changed.'),
    ('Close this window or press Ctrl+C to stop.',
        'Close this window or press Ctrl+C to sto'
        'p changed.'), ('The page is served only when {}',
        'The page is served changed only when {}')]
command = ['python3', '-B', 'scripts/verify-fast-mode-script.py',
    'Style.test_every_copied_message_and_exit_code_matches_its_source']
try:
    control = subprocess.run(command, capture_output=True, timeout=15)
    assert control.returncode == 0, control.stderr.decode()
    for old, new in cases:
        assert source.count(old) == 1, (old, source.count(old))
        path.write_text(source.replace(old, new))
        result = subprocess.run(command, capture_output=True, timeout=15)
        assert result.returncode == 1, result.stderr.decode()
        assert b'FAILED (failures=1)' in result.stderr, result.stderr.decode()
        print('Caught:', old)
        path.write_bytes(baseline)
finally:
    path.write_bytes(baseline)
assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(baseline).digest()
print('16 drifts caught; exact source bytes restored.')
