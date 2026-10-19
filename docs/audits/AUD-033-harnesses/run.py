"""Record source-bound checks, process memory and the machine reserve locally."""

import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
INPUTS = Path(__file__).resolve().parent
HERE = ROOT / "docs/audits/AUD-033-evidence"
HERE.mkdir(exist_ok=True)
RSS_LIMIT = int(os.environ.get('MHFE_CHECK_RSS_LIMIT_KIB', 2560 * 1024))
if not 0 < RSS_LIMIT <= 2560 * 1024:
    raise ValueError('Invalid task memory limit')
RESERVE = 3 * 1024 * 1024
ENVIRONMENT = {
    'CARGO_HOME': str(ROOT.parent / 'workingspace/cargo'),
    'RUSTUP_HOME': str(ROOT.parent / 'workingspace/rustup'),
    'CARGO_BUILD_JOBS': '1', 'RUST_TEST_THREADS': '1', 'EMCC_CORES': '1',
}


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def snapshot():
    names = subprocess.check_output([
        'git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard',
    ], cwd=ROOT).decode().split('\0')
    files = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
             for name in sorted(set(names)) if name and not name.startswith('docs/audits/')
             and (ROOT / name).is_file()}
    identity = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return {'files': files, 'sha256': identity}


def memory(pid):
    processes = {}
    for folder in Path('/proc').iterdir():
        if not folder.name.isdigit():
            continue
        try:
            fields = (folder / 'stat').read_text().rsplit(')', 1)[1].split()
            rss = int((folder / 'statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE') // 1024
            processes[int(folder.name)] = (int(fields[1]), int(fields[2]), rss, fields[0])
        except (OSError, ValueError, IndexError):
            continue
    selected = {pid}
    while True:
        previous = len(selected)
        selected.update(p for p, (parent, group, _, _) in processes.items()
                        if parent in selected or group == pid)
        if len(selected) == previous:
            break
    rss = sum(size for p, (_, _, size, _) in processes.items() if p in selected)
    live = sum(1 for p, (_, _, _, state) in processes.items()
               if p in selected and state not in {'Z', 'X'})
    available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()
                     if line.startswith('MemAvailable:'))
    return rss, available, live


def stop(process):
    # Do not reap the leader until the final group signal: its PID must stay reserved.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait(timeout=5)
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def main():
    name, timeout, *command = sys.argv[1:]
    if not name.replace('-', '').replace('_', '').isalnum() or not command:
        raise ValueError('Expected a plain result name, timeout in seconds, then argv')
    timeout = float(timeout)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('Expected a finite positive timeout in seconds')
    log = HERE / f'{name}.log'
    record_path = HERE / f'{name}.command.json'
    if log.exists() or record_path.exists():
        raise ValueError('Preserve old evidence; choose a fresh result name')
    before = snapshot()
    runner_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    # Keep the exact private helpers too, including nested shell/Python inputs.
    # An edited helper must not be mistaken for the bytes of an earlier run.
    helper_root = HERE / 'helper-snapshots'
    helper_root.mkdir(exist_ok=True)
    helper_hashes = {}
    for helper in sorted(INPUTS.iterdir()):
        if not helper.is_file() or helper.suffix not in {'.py', '.sh', '.mjs', '.c'}:
            continue
        content = helper.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        saved = helper_root / digest
        if saved.exists():
            if hashlib.sha256(saved.read_bytes()).hexdigest() != digest:
                raise ValueError('A retained helper snapshot has changed')
        else:
            with saved.open('xb') as retained:
                retained.write(content)
        helper_hashes[helper.name] = digest
    argv_files = {}
    for argument in command:
        if len(argument) > 4096 or '\n' in argument:
            continue
        candidate = Path(argument)
        if candidate.suffix not in {'.py', '.sh', '.mjs', '.rs', '.c', '.h'}:
            continue
        path = candidate if candidate.is_absolute() else ROOT / candidate
        if not path.is_file():
            continue
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        retained = helper_root / digest
        if retained.exists():
            if hashlib.sha256(retained.read_bytes()).hexdigest() != digest:
                raise ValueError('A retained argv script has changed')
        else:
            with retained.open('xb') as stream:
                stream.write(content)
        argv_files[argument] = digest
    checkpoint_path = HERE / f'{name}.progress.json'
    env = dict(os.environ, **ENVIRONMENT)
    started = utc()
    peak = 0
    minimum = None
    reason = None
    last_checkpoint = 0.0

    def checkpoint(status, pid=None):
        value = {
            'status': status, 'argv': command, 'sourceBefore': before,
            'startedUtc': started, 'lastSeenUtc': utc(), 'pid': pid,
            'runnerSha256': runner_hash, 'environment': ENVIRONMENT,
            'privateHelperSha256': helper_hashes,
            'argvSourceFiles': argv_files,
            'sampledDescendantPeakRssKiB': peak,
            'minimumMachineMemAvailableKiB': minimum,
            'rssLimitKiB': RSS_LIMIT, 'machineReserveKiB': RESERVE,
        }
        temporary = checkpoint_path.with_suffix('.tmp')
        temporary.write_text(json.dumps(value, indent=2) + '\n')
        temporary.replace(checkpoint_path)
    _, available, _ = memory(os.getpid())
    if available < RESERVE + RSS_LIMIT:
        raise RuntimeError(f'Not enough available memory for budget plus reserve: {available} KiB')
    checkpoint('starting')
    try:
        with log.open('xb') as output:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            checkpoint('running', process.pid)
            deadline = time.monotonic() + timeout
            while True:
                # WNOWAIT observes exit without releasing the group leader's PID. A live
                # same-group child remains subject to budgets after an ordinary leader exit.
                exited = os.waitid(os.P_PID, process.pid,
                                   os.WEXITED | os.WNOHANG | os.WNOWAIT)
                rss, available, live = memory(process.pid)
                peak = max(peak, rss)
                minimum = available if minimum is None else min(minimum, available)
                if time.monotonic() - last_checkpoint >= 5:
                    checkpoint('running', process.pid)
                    last_checkpoint = time.monotonic()
                if exited is not None and live == 0:
                    break
                if rss > RSS_LIMIT or available < RESERVE or time.monotonic() > deadline:
                    reason = ('process-memory' if rss > RSS_LIMIT else
                              'machine-reserve' if available < RESERVE else 'wall-timeout')
                    stop(process)
                    break
                time.sleep(0.25)
            result = process.wait()
    except BaseException:
        if 'process' in locals():
            stop(process)
        raise
    after = snapshot()
    record = {
        'argv': command, 'cwd': str(ROOT), 'environment': ENVIRONMENT,
        'startedUtc': started, 'endedUtc': utc(), 'exitCode': result,
        'terminationReason': reason, 'timeoutSeconds': float(timeout),
        'sourceBefore': before, 'sourceAfter': after,
        'sourceUnchanged': before == after,
        'runnerSha256': runner_hash,
        'privateHelperSha256': helper_hashes,
        'argvSourceFiles': argv_files,
        'logSha256': hashlib.sha256(log.read_bytes()).hexdigest(),
        'sampledDescendantPeakRssKiB': peak, 'minimumMachineMemAvailableKiB': minimum,
        'rssLimitKiB': RSS_LIMIT, 'machineReserveKiB': RESERVE,
        'dockerLimitation': 'Daemon-owned containers are not descendant RSS; bound via buildx resource flags and global reserve.',
    }
    status = 124 if reason == 'wall-timeout' else 1 if reason is not None else result
    if status == 0 and not record['sourceUnchanged']:
        status = 1
    record['wrapperExitCode'] = status
    record_path.write_text(json.dumps(record, indent=2) + '\n')
    checkpoint('completed', process.pid)
    print(json.dumps({k: record[k] for k in ['exitCode', 'wrapperExitCode', 'terminationReason', 'sourceUnchanged',
                                           'sampledDescendantPeakRssKiB',
                                           'minimumMachineMemAvailableKiB']}), flush=True)
    return status


if __name__ == '__main__':
    sys.exit(main())
