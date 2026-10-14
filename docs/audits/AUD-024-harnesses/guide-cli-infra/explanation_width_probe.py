"""AUD-024 (guide-cli-infra): the width of the lines that `?` shows at the container-length
question of `mhfe encrypt` for a 12-word phrase (style::gives and style::costs, which do not wrap).
Types the public test phrase "abandon ... about" and stops at the question, before any password,
so no Argon2 round runs. Rule CORE-36: running text wraps at 78 columns (style::TEXT_WIDTH).
Exit 1 when a line of the explanation is wider than 78 columns."""
import os, pty, re, select, signal, sys, time, unicodedata
mhfe = os.path.abspath(sys.argv[1])
PHRASE = " ".join(["abandon"] * 11 + ["about"])
env = dict(os.environ, TERM="xterm-256color", COLUMNS="100")
env.pop("NO_COLOR", None)
pid, fd = pty.fork()
if pid == 0:
    os.execve(mhfe, [mhfe, "encrypt", "--pim", "0", "--mem", "0", "--new-password", "own",
                     "--repair-words", "0"], env)
out = b""
def pump(seconds, until=None, since=0):
    global out
    end = time.time() + seconds
    while time.time() < end:
        if until and until in out[since:]:
            return True
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                out += os.read(fd, 65536)
            except OSError:
                return False
    return bool(until and until in out[since:])
seen = pump(15, b"seed phrase")
time.sleep(0.4)
mark = len(out)
os.write(fd, PHRASE.encode() + b"\r")
steps = [seen]
# Any question before the length question is answered with its default (Enter).
for _ in range(4):
    if pump(5, b"How long should the encrypted phrase be", mark):
        break
    time.sleep(0.4)
    mark = len(out)
    os.write(fd, b"\r")
asked = b"How long should the encrypted phrase be" in out
time.sleep(0.4)
mark = len(out)
os.write(fd, b"?")
pump(2)
os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", out[mark:].decode("utf-8", "replace"))
def cells(line):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in line)
lines = [line.rstrip("\r") for line in text.split("\n")]
marked = [(cells(line), line) for line in lines if line.startswith("  ✓") or line.startswith("  !")]
for width, line in marked:
    print(f"{width:3} {line}")
widest = max((width for width, _ in marked), default=0)
print(f"question reached: {asked}; widest explanation line: {widest} columns (TEXT_WIDTH 78)")
defect = widest > 78
print("DEFECT REPRODUCED" if defect else "DEFECT NOT REPRODUCED")
sys.exit(1 if defect else 0)
