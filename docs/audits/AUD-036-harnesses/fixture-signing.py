"""Check modified-public-fixture signing dispatch, not native macOS enforcement."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
BASE = 'c059b1afb00584d9a99fefe37247448b5ec7f3cd'
SOURCE = 'scripts/terminal_suite/self_test.py'


def main():
    if sys.flags.optimize:
        raise RuntimeError('Run without Python optimization; fixture assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', action='store_true')
    args = parser.parse_args()
    scratch = ROOT.parent / 'tmp/mhfe-aud036-fixtures'
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='public-signing-', dir=scratch) as temporary:
        folder = Path(temporary)
        original = folder / 'public-probe'
        marker = b'MHFE_SYNTHETIC_FIXTURE_MARKER'
        content = b'public-prefix\n' + marker + b'\npublic-suffix'
        original.write_bytes(content)
        # The PTY constants normally parse the actual checker argv at import.
        sys.argv = [sys.argv[0], str(original)]
        sys.path.insert(0, str(ROOT / 'scripts'))
        if args.baseline:
            source = subprocess.check_output(['git', 'show', BASE + ':' + SOURCE], cwd=ROOT)
            module = types.ModuleType('terminal_suite.retained_signing_probe')
            module.__package__ = 'terminal_suite'
            exec(compile(source, '<retained-public-fixture-helper>', 'exec'), module.__dict__)
        else:
            from terminal_suite import self_test as module
            source = (ROOT / SOURCE).read_bytes()
        module.PROGRAM = str(original)
        altered = bytearray(content)
        altered[content.index(marker) + len(marker) - 1] ^= 1
        for platform in ['darwin', 'linux']:
            destination = folder / platform
            destination.mkdir()
            with patch.object(module.sys, 'platform', platform), \
                    patch.object(module.subprocess, 'run') as signer:
                output = Path(module.damaged_copy(destination, marker))
                assert output.read_bytes() == altered
                assert original.read_bytes() == content
                if platform == 'darwin':
                    signer.assert_called_once_with(
                        [str(ROOT / 'scripts/harden-macos.sh'), str(output)],
                        check=True, capture_output=True, timeout=30)
                else:
                    signer.assert_not_called()
        refused = folder / 'refused'
        refused.mkdir()
        with patch.object(module.sys, 'platform', 'darwin'), \
                patch.object(module.subprocess, 'run',
                             side_effect=subprocess.CalledProcessError(1, ['public-signer'])):
            try:
                module.damaged_copy(refused, marker)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError('a refused signer was accepted')
        print('PASS: Darwin shares runtime signing; Linux does not sign; refusal propagates')
        print('sourceSha256=' + hashlib.sha256(source).hexdigest())
        print('Native macOS signing and the real damaged-KAT report remain separate checks.')


if __name__ == '__main__':
    main()
