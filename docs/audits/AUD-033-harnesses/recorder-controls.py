"""Finite public subprocess controls for the evidence recorder, without repository edits."""
from pathlib import Path
import json
import os
import signal
import subprocess
import sys
import unittest

root = Path.cwd()
local = root / 'docs/audits/AUD-033-evidence/recorder-controls'
local.mkdir(parents=True, exist_ok=True)
runner = root / 'docs/audits/AUD-033-harnesses/run.py'
evidence = root / 'docs/audits/AUD-033-evidence'
prefix = sys.argv[1]
if not prefix.replace('-', '').replace('_', '').isalnum():
    raise SystemExit('Use a plain unique control prefix.')
sys.argv = [sys.argv[0]]
environment = dict(os.environ, MHFE_CHECK_RSS_LIMIT_KIB='131072')


def invoke(name, timeout, code):
    label = f'guard-{prefix}-{name}'
    result = subprocess.run([sys.executable, str(runner), label, timeout,
                             sys.executable, '-c', code],
                            cwd=root, env=environment, capture_output=True, timeout=20)
    return result, evidence / f'{label}.command.json'


class GuardControls(unittest.TestCase):
    def test_invalid_deadlines_never_start_the_child(self):
        for value in ['nan', 'inf', '-inf', '0', '-1']:
            with self.subTest(timeout=value):
                marker = local / f'guard-{prefix}-{value}-started'
                self.assertFalse(marker.exists())
                code = f'from pathlib import Path; Path({str(marker)!r}).write_text("public")'
                result, _ = invoke(value.replace('-', 'minus'), value, code)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists(), 'invalid deadline started the child')

    def test_a_terminated_zero_exit_is_still_a_failed_command(self):
        code = 'import signal,sys,time; signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); time.sleep(10)'
        result, receipt = invoke('terminated-zero', '0.5', code)
        record = json.loads(receipt.read_text())
        self.assertEqual(record['terminationReason'], 'wall-timeout')
        self.assertEqual(record['exitCode'], 0, 'retain the actual child status')
        self.assertNotEqual(result.returncode, 0, 'termination cannot become a green result')

    def test_termination_stops_the_whole_owned_process_group(self):
        self.assert_group_stopped('grandchild', leader_waits=True)

    def test_an_exited_leader_does_not_abandon_its_live_group(self):
        self.assert_group_stopped('exited-leader', leader_waits=False)

    def assert_group_stopped(self, name, *, leader_waits):
        marker = local / f'guard-{prefix}-{name}.json'
        grandchild = ('import json,os,signal,time; from pathlib import Path; '
                      'signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                      f'Path({str(marker)!r}).write_text(json.dumps([os.getpid(),os.getpgrp()])); '
                      'time.sleep(30)')
        code = ('import signal,subprocess,sys,time; '
                'signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); '
                f'subprocess.Popen([sys.executable,"-c",{grandchild!r}]); '
                + ('time.sleep(10)' if leader_waits else 'sys.exit(0)'))
        pid = group = None
        try:
            result, _ = invoke(name, '1', code)
            pid, group = json.loads(marker.read_text())
            stat = Path(f'/proc/{pid}/stat')
            live = stat.exists() and stat.read_text().rsplit(')', 1)[1].split()[0] != 'Z'
            self.assertFalse(live, 'a SIGTERM-resistant grandchild survived group cleanup')
            self.assertNotEqual(result.returncode, 0)
        finally:
            if pid is not None:
                try:
                    if os.getpgid(pid) == group:
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_a_normal_success_stays_successful(self):
        result, receipt = invoke('normal', '5', 'print("public normal result")')
        self.assertEqual(result.returncode, 0)
        self.assertIsNone(json.loads(receipt.read_text())['terminationReason'])


unittest.main()
