"""AUD-024 (guide-cli-infra): what the container password prompt of `mhfe decrypt` says at a
terminal that can redraw (TERM=xterm-256color) and at TERM=dumb. Types the public zero-12 suite 3
vector container (tests/fixtures/suite3-vectors/zero-12.json) and stops at the password prompt,
before any password is typed, so no Argon2 round runs.

Rule CORE-39: every password or passphrase prompt says which secret it is and what it does.
Exit 1 when the TERM=dumb prompt lacks the explanation the other terminal shows."""
import json, os, pty, re, select, signal, sys, time
mhfe = os.path.abspath(sys.argv[1])
container = json.load(open("tests/fixtures/suite3-vectors/zero-12.json"))["container"]
EXPLANATION = "it is NOT a BIP39 passphrase"

def run(term):
    env = dict(os.environ, TERM=term)
    env.pop("NO_COLOR", None)
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(mhfe, [mhfe, "decrypt", "--pim", "0", "--mem", "0", "--words", "24"], env)
    out = b""
    def pump(seconds, until=None):
        nonlocal out
        end = time.time() + seconds
        while time.time() < end:
            if until and until in out:
                return True
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    out += os.read(fd, 65536)
                except OSError:
                    return False
        return bool(until and until in out)
    pump(10, b"seed phrase: ")
    time.sleep(0.4)
    os.write(fd, container.encode() + b"\r")
    reached = pump(10, b"password")
    pump(1.0)
    os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", out.decode("utf-8", "replace"))
    tail = text[text.rfind("Container,"):]
    lines = [line.strip() for line in tail.splitlines() if line.strip()]
    return reached, EXPLANATION in tail, lines[-4:]

defect = False
for term in ("xterm-256color", "dumb"):
    reached, explained, last = run(term)
    print(f"TERM={term}: password prompt reached: {reached}; explanation shown: {explained}; last lines: {last}")
    if term == "dumb":
        defect = reached and not explained
print("DEFECT REPRODUCED" if defect else "DEFECT NOT REPRODUCED")
sys.exit(1 if defect else 0)
