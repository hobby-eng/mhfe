"""AUD-024 (guide-cli-infra): how mhfe reports an isolation boundary that the kernel refuses.

Linux x86-64 only. Runs the release binary twice, once as it is and once under a seccomp filter
that answers landlock_create_ruleset with ENOSYS, as a kernel without Landlock (before Linux 5.13,
or with Landlock off) does. Under that filter mhfe cannot install its write ruleset. For each run
it records the "Isolation" row of `mhfe self-test` and the "Isolation" line of the settings summary
of `mhfe encrypt --pim 0 --mem 0 ...` at TERM=dumb, read before the first secret prompt (the
process is then killed; nothing secret is typed and no Argon2 round runs).

Rule RUST-11: a protection the system refuses is reported, never assumed; README: the self-test
marks a weaker protection with a yellow "!". Exit 1 when, with the write ruleset refused, the
self-test still reports isolation as fully enforced and the summary gives no warning.
"""
import ctypes, os, pty, re, select, signal, struct, subprocess, sys, time

MHFE = os.path.abspath(sys.argv[1])
SYS_LANDLOCK_CREATE_RULESET = 444  # x86-64
AUDIT_ARCH_X86_64 = 0xC000003E
ENOSYS = 38


def without_landlock_then_exec(argv):
    """Installs the filter in this process, then executes argv (used in a forked child)."""
    def ins(code, jt, jf, k):
        return struct.pack("HBBI", code, jt, jf, k)
    BPF_LD_W_ABS, BPF_JEQ_K, BPF_RET_K = 0x20, 0x15, 0x06
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO = 0x7FFF0000, 0x00050000
    program = b"".join([
        ins(BPF_LD_W_ABS, 0, 0, 4),                          # arch
        ins(BPF_JEQ_K, 0, 3, AUDIT_ARCH_X86_64),             # other arch: allow
        ins(BPF_LD_W_ABS, 0, 0, 0),                          # nr
        ins(BPF_JEQ_K, 0, 1, SYS_LANDLOCK_CREATE_RULESET),
        ins(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | ENOSYS),
        ins(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
    ])
    buffer = ctypes.create_string_buffer(program)
    prog = struct.pack("HxxxxxxQ", len(program) // 8, ctypes.addressof(buffer))
    prog_buffer = ctypes.create_string_buffer(prog)
    libc = ctypes.CDLL(None, use_errno=True)
    # A pointer argument must not be cut to a C int.
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_ulong]
    PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER = 38, 22, 2
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        os._exit(90)
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(prog_buffer), 0, 0) != 0:
        os._exit(91)
    os.execv(argv[0], argv)


def self_test_row(block):
    read, write = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        os.dup2(write, 1); os.dup2(write, 2)
        devnull = os.open("/dev/null", os.O_RDONLY); os.dup2(devnull, 0)
        argv = [MHFE, "self-test"]
        if block:
            without_landlock_then_exec(argv)
        os.execv(argv[0], argv)
    os.close(write)
    out = b""
    while True:
        chunk = os.read(read, 65536)
        if not chunk:
            break
        out += chunk
    os.waitpid(pid, 0)
    text = re.sub(r"\x1b\[[0-9;]*m", "", out.decode("utf-8", "replace"))
    rows = [line.strip() for line in text.splitlines() if line.strip().startswith("Isolation")]
    return rows[0] if rows else "(no row)"


def summary_line(block):
    argv = [MHFE, "encrypt", "--pim", "0", "--mem", "0", "--same-length", "no",
            "--new-password", "own", "--repair-words", "0"]
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "dumb"
        if block:
            without_landlock_then_exec(argv)
        os.execv(argv[0], argv)
    out = b""
    end = time.time() + 15
    while time.time() < end and b"seed phrase" not in out:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                out += os.read(fd, 65536)
            except OSError:
                break
    os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
    text = re.sub(r"\x1b\[[0-9;]*m", "", out.decode("utf-8", "replace"))
    lines = [line.strip() for line in text.splitlines()]
    isolation = [line for line in lines if line.startswith("Isolation")]
    warnings = [line for line in lines if line.startswith("!")]
    if not isolation:
        print("  (output before the prompt:", " | ".join(line for line in lines if line), ")")
    return (isolation[0] if isolation else "(no Isolation line)"), warnings


defect = False
for block in (False, True):
    name = "write ruleset refused (landlock_create_ruleset gives ENOSYS)" if block else "as it is"
    row = self_test_row(block)
    line, warnings = summary_line(block)
    print(f"{name}:\n  self-test row: {row}\n  encrypt summary: {line}\n  warnings: {warnings}")
    if block:
        defect = row.endswith("enforced") and "file writes" not in line and not warnings
print("DEFECT REPRODUCED" if defect else "DEFECT NOT REPRODUCED")
sys.exit(1 if defect else 0)
