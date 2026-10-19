import json
import os
import subprocess
import sys
if sys.flags.optimize:
    raise SystemExit('Run audit harnesses without Python optimization')
binary = sys.argv[1]
env = dict(os.environ, NO_COLOR='1')
results = []
separators = [
    ('single', ''), ('LF', '\n'), ('CR', '\r'),
    ('CRLF', '\r\n'), ('NEL', '\x85'), ('LS', '\u2028'),
]
for name, separator in separators:
    value = 'AUD026-FIRST' + separator + 'AUD026-SECOND'
    child = subprocess.run(
        [binary, 'encrypt', '--pim', value], capture_output=True,
        text=True, env=env, timeout=10,
    )
    output = child.stdout + child.stderr
    leaked = 'AUD026-FIRST' in output or 'AUD026-SECOND' in output
    assert child.returncode == 2, (name, child.returncode, output)
    results.append({
        'separator': name, 'exitCode': child.returncode,
        'syntheticMarkerEchoed': leaked,
        'stdout': child.stdout, 'stderr': child.stderr,
    })
print(json.dumps(results, indent=2, ensure_ascii=True))
assert not results[0]['syntheticMarkerEchoed'], (
    'Single-line control must be redacted'
)
sys.exit(1 if any((v['syntheticMarkerEchoed'] for v in results)) else 0)
