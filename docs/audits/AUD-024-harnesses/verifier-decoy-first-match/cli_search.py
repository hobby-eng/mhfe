"""AUD-024 verifier: drives `mhfe repair` in a pseudo-terminal at TERM=dumb (numbered menus, no
private screen) through the missing-word search with the container's own wallet. The container
phrase is "abandon" x10 "? ?" (public test data); the fingerprint 02ba9d7a is that of
"abandon x10 employ giraffe", which "abandon x10 amused buzz" shares. No Argon2 runs in this
search (only the startup known-answer checks at their reduced size). Stops with Ctrl+C at the
question whether to use the found container phrase. Exits 1 when the tool offers "amused buzz"."""
import os, pty, re, select, sys, time

binary = sys.argv[1]
env = dict(os.environ, TERM="dumb", NO_COLOR="1", COLUMNS="100", LINES="40")
env.pop("CI", None)
pid, fd = pty.fork()
if pid == 0:
    os.execve(binary, [binary, "repair"], env)

log = b""
def wait_for(pattern, limit):
    global log
    end = time.time() + limit
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            log += chunk
            if re.search(pattern, log.decode("utf-8", "replace")):
                return True
    return False

def send(text):
    time.sleep(0.3)
    os.write(fd, text.encode())

steps = [
    (r"Container[^\n]*: *$", "abandon " * 10 + "? ?\r", 60),
    (r"Repair words: *$", "\r", 60),
    (r"what do you know\?[\s\S]*\n[^\n]*$", None, 30),
]
ok = True
for pattern, answer, limit in steps:
    if not wait_for(pattern, limit):
        ok = False
        break
    if answer is not None:
        send(answer)
if ok:
    time.sleep(1.0)
    wait_for(r"$^", 1)
    send("1\r")  # The container's own wallet
    ok = wait_for(r"Address or master key fingerprint: *$", 30)
if ok:
    send("02ba9d7a\r")
    ok = wait_for(r"passphrase used with[\s\S]*\n[^\n]*$", 30)
if ok:
    time.sleep(1.0)
    wait_for(r"$^", 1)
    send("1\r")  # No
    ok = wait_for(r"Use the found container phrase\?[\s\S]*\n[^\n]*$", 600)
time.sleep(1.5)
wait_for(r"$^", 1)
os.write(fd, b"\x03")
wait_for(r"$^", 3)
try:
    os.kill(pid, 9)
except ProcessLookupError:
    pass
text = log.decode("utf-8", "replace").replace("\r\n", "\n")
# The progress line is redrawn with carriage returns: keep each state on its own line.
text = re.sub(r"\r", "\n", text)
print(text)
offered = "amused" in text and "buzz" in text and "Found container phrase" in text
print("RESULT:", "the tool offers abandon x10 amused buzz as the found container phrase"
      if offered else "the wrong container was not offered (or the run did not reach it)")
sys.exit(1 if offered else (0 if ok else 2))
