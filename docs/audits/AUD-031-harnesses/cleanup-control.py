"""A public synthetic child proves the CLI probe cleans up after its recovery tripwire."""

import errno
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import signal
import time


path = Path(__file__).with_name("cli-refusal.py")
spec = importlib.util.spec_from_file_location("aud031_cli_probe", path)
if spec is None or spec.loader is None:
    raise SystemExit("The CLI audit helper could not be loaded")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
session = module.Session.__new__(module.Session)
pid, fd = pty.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(1, b"Recovering public synthetic control\n")
    time.sleep(30)
    os._exit(0)

session.pid = pid
session.fd = fd
session.status = None
session.transcript = bytearray()
session.deadline = time.monotonic() + 5
cleanup_error = None
reaped = False
closed = False
try:
    ready, _, _ = select.select([fd], [], [], 5)
    if not ready:
        raise TimeoutError("The synthetic child did not announce readiness")
    session.transcript.extend(os.read(fd, 1024))
    if b"Recovering" not in session.transcript:
        raise RuntimeError("The synthetic recovery marker was not observed")
    try:
        session.close()
    except RuntimeError as error:
        cleanup_error = str(error)
    try:
        observed, _ = os.waitpid(pid, os.WNOHANG)
        reaped = observed != 0
    except ChildProcessError:
        reaped = True
    try:
        os.fstat(fd)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        closed = True
    print(json.dumps({
        "syntheticRecoveryMarker": True,
        "cleanupError": cleanup_error,
        "ownedChildReaped": reaped,
        "ptyClosed": closed,
        "productionBinaryStarted": False,
    }), flush=True)
    if cleanup_error is not None or not reaped or not closed:
        raise SystemExit("The recovery tripwire interrupted owned-process cleanup")
finally:
    # This control owns an independent fallback, including when the old helper is broken.
    if not reaped:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    if not closed:
        os.close(fd)
