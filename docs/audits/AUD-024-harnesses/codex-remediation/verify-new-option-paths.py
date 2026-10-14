"""
Run only the new option cases and record public command/flag coverage.
"""
import hashlib
import json
import sys
import tempfile
from pathlib import Path
scratch = Path('../tmp/aud024').resolve()
tempfile.tempdir = str(scratch)
sys.path.insert(0, str(Path('scripts').resolve()))
from terminal_suite import option_paths as cases
from terminal_suite.session import Session
calls = []
original_session = Session.__init__


def session(self, arguments=(), **kwargs):
    calls.append(tuple(arguments))
    return original_session(self, arguments, **kwargs)


Session.__init__ = session
original_plain = cases.run_plainly


def plain(arguments, *args, **kwargs):
    calls.append(tuple(arguments))
    return original_plain(arguments, *args, **kwargs)


cases.run_plainly = plain
for name in ['scan_gap_options_refuse_invalid_values_and_skip_the_gap_question',
    'explicit_check_paths_are_used_and_misplaced_paths_are_refused',
    'a_check_word_password_has_the_librarys_check_word',
    'explicit_repair_options_ask_for_the_card_before_the_password',
    'passphrase_repair_password_and_memory_options_reach_their_preflights',
    'test_tool_options_refuse_bad_selections_before_any_argon2_work']:
    print('Case:', name, flush=True)
    getattr(cases, name)()
actual = {(args[0], arg) for args in calls for arg in args[1:] if arg.startswith('--')}
wanted = {(command, '--scan-gap') for command in ['decrypt', 'check', 'rekey', 'wallets',
        'repair']}
wanted |= {('check', '--path'), ('password', '--check-word')}
wanted |= {(command, '--repair') for command in ['decrypt', 'rekey', 'wallets']}
wanted |= {(command, '--passphrase-used') for command in ['decrypt', 'rekey']}
wanted |= {('rekey', '--repair-words'), ('new', '--new-password'), ('new', '--mem'),
    ('wallets', '--mem'), ('test-vectors', '--only'), ('test-vectors', '--output'),
    ('test-vectors', '--same-length'), ('test-benchmark', '--pim'), ('test-benchmark',
        '--mem')}
assert wanted <= actual, sorted(wanted - actual)
Path('../tmp/aud024/cli-option-runtime-coverage.json').write_text(json.dumps({
    'wantedPairs': sorted(wanted),
    'observedPairs': sorted(actual),
    'publicCommands': calls,
    'sourceSha256': hashlib.sha256(
        Path('scripts/terminal_suite/option_paths.py').read_bytes()
    ).hexdigest(),
}, indent=2) + '\n')
print('All', len(wanted), 'required command/flag pairs ran; no full-size Argon2 was entered.')
