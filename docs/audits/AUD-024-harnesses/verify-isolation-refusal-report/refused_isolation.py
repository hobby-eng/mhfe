"""AUD-024 verifier probe: what mhfe says when the kernel refuses one isolation boundary.

Linux x86-64 only. Runs the given mhfe binary under a seccomp filter (installed in a forked
child before exec) that makes one system call fail, as a kernel without that feature does:
  landlock  - landlock_create_ruleset (444) returns ENOSYS: a kernel without Landlock
  seccomp   - prctl(PR_SET_SECCOMP, ...) returns EINVAL: a kernel without seccomp filters
  unshare   - unshare (272) returns EPERM: no user namespaces allowed (documented as optional)
For each case it prints the full ANSI-stripped output of `mhfe self-test` (stdin /dev/null) and of
`mhfe encrypt --pim 0 --mem 0 ...` at TERM=dumb in a pty, read up to the first secret prompt; the
encrypt process is then killed. Nothing is typed; no Argon2 round of the command runs.
Exit 1 when, in the landlock case, the self-test isolation row still reads "enforced" with no "!"
and the encrypt output has no line that mentions file writes or Landlock.
"""
import ctypes, os, pty, re, select, signal, struct, sys, time

MHFE = os.path.abspath(sys.argv[1])
ARCH_X86_64 = 0xC000003E
NR_PRCTL, NR_UNSHARE, NR_LANDLOCK_CREATE = 157, 272, 444
PR_SET_SECCOMP, PR_SET_NO_NEW_PRIVS, SECCOMP_MODE_FILTER = 22, 38, 2
ENOSYS, EINVAL, EPERM = 38, 22, 1
LD_ABS, JEQ, RET = 0x20, 0x15, 0x06
ALLOW, ERRNO = 0x7FFF0000, 0x00050000

CASES = {
    "as-is": [],
    "landlock": [(NR_LANDLOCK_CREATE, None, ENOSYS)],
    "seccomp": [(NR_PRCTL, PR_SET_SECCOMP, EINVAL)],
    "unshare": [(NR_UNSHARE, None, EPERM)],
}


def ins(code, jt, jf, k):
    return struct.pack("HBBI", code, jt, jf, k)


def program(rules):
    blocks = []
    for nr, arg0, errno in rules:
        if arg0 is None:
            blocks += [ins(JEQ, 0, 1, nr), ins(RET, 0, 0, ERRNO | errno)]
        else:
            blocks += [ins(JEQ, 0, 4, nr), ins(LD_ABS, 0, 0, 16), ins(JEQ, 0, 1, arg0),
                       ins(RET, 0, 0, ERRNO | errno), ins(LD_ABS, 0, 0, 0)]
    return b"".join([ins(LD_ABS, 0, 0, 4), ins(JEQ, 0, 1 + len(blocks), ARCH_X86_64),
                     ins(LD_ABS, 0, 0, 0)] + blocks + [ins(RET, 0, 0, ALLOW)])


def exec_with(rules, argv):
    if rules:
        code = program(rules)
        buf = ctypes.create_string_buffer(code)
        fprog = ctypes.create_string_buffer(struct.pack("HxxxxxxQ", len(code) // 8,
                                                        ctypes.addressof(buf)))
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            os._exit(90)
        if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(fprog), 0, 0) != 0:
            os._exit(91)
    os.execv(argv[0], argv)


def plain(data):
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", data.decode("utf-8", "replace"))


def self_test(rules):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.dup2(w, 1); os.dup2(w, 2)
        os.dup2(os.open("/dev/null", os.O_RDONLY), 0)
        exec_with(rules, [MHFE, "self-test"])
    os.close(w)
    out = b""
    while True:
        chunk = os.read(r, 65536)
        if not chunk:
            break
        out += chunk
    _, status = os.waitpid(pid, 0)
    return plain(out), os.waitstatus_to_exitcode(status)


def encrypt_summary(rules):
    argv = [MHFE, "encrypt", "--pim", "0", "--mem", "0", "--same-length", "no",
            "--new-password", "own", "--repair-words", "0"]
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "dumb"
        exec_with(rules, argv)
    out, end = b"", time.time() + 20
    while time.time() < end and b"seed phrase" not in out:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                out += os.read(fd, 65536)
            except OSError:
                break
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    return plain(out)


results = {}
for name, rules in CASES.items():
    text, code = self_test(rules)
    row = next((l.strip() for l in text.splitlines() if l.strip().startswith("Isolation")), "(none)")
    enc = encrypt_summary(rules)
    enc_lines = [l.rstrip() for l in enc.replace("\r", "\n").splitlines() if l.strip()]
    print(f"=== case {name}: rules {rules}")
    print(f"  self-test exit {code}; isolation row: {row!r}")
    print("  encrypt output up to the first secret prompt:")
    for l in enc_lines:
        print("    | " + l)
    results[name] = (row, enc_lines)

row, lines = results["landlock"]
mentions = [l for l in lines if re.search(r"write|landlock", l, re.I)]
defect = row.endswith("enforced") and "!" not in row and not mentions
print("landlock case: self-test row", repr(row), "; lines naming writes/Landlock:", mentions)
print("DEFECT REPRODUCED" if defect else "DEFECT NOT REPRODUCED")
sys.exit(1 if defect else 0)
