"""Runs `mhfe repair-words --count 4` in a pseudo-terminal under several colour environments and
reports whether the output up to the container prompt holds colour codes (ESC [ ... m).

Public data only: nothing is typed; the process is ended once the prompt appears."""
import os, pty, re, select, signal, sys, time
mhfe = sys.argv[1]
cases = [
    ("TERM=xterm-256color", {"TERM": "xterm-256color"}),
    ("TERM=dumb", {"TERM": "dumb"}),
    ("NO_COLOR=1", {"TERM": "xterm-256color", "NO_COLOR": "1"}),
    ("CLICOLOR=0", {"TERM": "xterm-256color", "CLICOLOR": "0"}),
    ("TERM=dumb CLICOLOR_FORCE=1", {"TERM": "dumb", "CLICOLOR_FORCE": "1"}),
]
for name, extra in cases:
    env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "TERM")}
    env.update(extra)
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(mhfe, [mhfe, "repair-words", "--count", "4"], env)
    out = b""
    end = time.time() + 5
    while time.time() < end and b"seed phrase:" not in out:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                out += os.read(fd, 65536)
            except OSError:
                break
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    sgr = len(re.findall(rb"\x1b\[[0-9;]*m", out))
    other = len(re.findall(rb"\x1b\[[0-9;?]*[A-Za-ln-z]", out))
    print(f"{name}: {sgr} colour codes, {other} other control sequences, prompt seen: {b'seed phrase:' in out}")
