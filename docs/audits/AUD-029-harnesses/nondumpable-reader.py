"""Linux-only control; ctypes supplies the OS FFI unavailable in Node's stdlib."""
import ctypes
import json
import os


if not __debug__:
    raise SystemExit('This assertion-based audit control refuses Python optimization')

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
LIBC.prctl.restype = ctypes.c_int
PR_GET_DUMPABLE = 3
PR_SET_DUMPABLE = 4


def observe(label):
    """Read process-policy metadata without reading any memory contents."""
    try:
        descriptor = os.open('/proc/self/mem', os.O_RDONLY)
        os.close(descriptor)
        opened, error = True, None
    except OSError as failure:
        opened, error = False, failure.errno
    result = {
        'phase': label,
        'dumpable': LIBC.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0),
        'selfMemOpen': opened,
        'openErrno': error,
        'procMemOwnerUid': os.stat('/proc/self/mem').st_uid,
        'effectiveUid': os.geteuid(),
    }
    print(json.dumps(result), flush=True)
    return result


before = observe('before')
assert before['selfMemOpen']
status = LIBC.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
assert status == 0
after = observe('after PR_SET_DUMPABLE=0')
assert after['dumpable'] == 0
assert not after['selfMemOpen']
assert after['openErrno'] == 13
assert after['procMemOwnerUid'] != after['effectiveUid']
print('PASS: child-only hardening reproduces the proc-reader acquisition refusal')
