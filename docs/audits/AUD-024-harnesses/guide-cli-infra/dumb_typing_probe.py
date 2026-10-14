"""AUD-023-UI004 recheck: at TERM=dumb, typing at the container prompt of `mhfe repair-words`
writes no control sequence (no word hints). Public letters only; killed after typing."""
import os, pty, re, select, signal, sys, time
mhfe = sys.argv[1]
env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR",)}
env["TERM"] = "dumb"
pid, fd = pty.fork()
if pid == 0:
    os.execve(mhfe, [mhfe, "repair-words", "--count", "4"], env)
out = b""
def pump(seconds):
    global out
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                out += os.read(fd, 65536)
            except OSError:
                return
pump(3)
before = len(out)
for key in [b"a", b"b", b"\x7f"]:
    os.write(fd, key)
    pump(0.3)
after = out[before:]
os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
escapes = re.findall(rb"\x1b\[[0-9;?]*[A-Za-z]", after)
print("bytes written after the prompt:", after)
print("control sequences after the prompt:", len(escapes))
sys.exit(1 if escapes else 0)
