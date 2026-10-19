import pathlib
import subprocess
import sys
import os
import json
if sys.flags.optimize:
    raise SystemExit('Run audit harnesses without Python optimization')
out = pathlib.Path(sys.argv[2])
assert not out.exists()
p = subprocess.run(
    [sys.argv[1], 'test-vectors', '--output', str(out),
     '--only', 'AUD026-NOT-A-VECTOR'],
    capture_output=True, text=True,
    env=dict(os.environ, NO_COLOR='1'), timeout=10,
)
print(json.dumps({
    'exitCode': p.returncode, 'stdout': p.stdout,
    'stderr': p.stderr, 'outputCreated': out.exists(),
}, indent=2))
assert not out.exists()
sys.exit(1 if 'AUD026-NOT-A-VECTOR' in p.stderr + p.stdout else 0)
