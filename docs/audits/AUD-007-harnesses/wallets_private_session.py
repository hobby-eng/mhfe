"""AUD-007 remediation check of SEC005: one real `mhfe wallets` session at full cost.

    python3 docs/audits/AUD-007-harnesses/wallets_private_session.py [path/to/mhfe]

The default program is target/release/mhfe. On the public zero-12 suite 3 container, the
container's own public password is refused (rule I29) and its message stays readable, a synthetic
password opens a 24-word wallet, and every wallet, its question and its number stay on one private
screen: the main screen, everything outside the alternate screen, shows none of them. Then
`mhfe decrypt` with that password must give the same wallet, unverified. It runs the self-test and
three recoveries at the default 2 GiB, about four minutes. Linux or macOS; no network, no files.
"""
import json, os, pty, re, select, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BINARY = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "target/release/mhfe")
vector = json.load(open(f"{ROOT}/tests/fixtures/suite3-vectors/zero-12.json"))
CONTAINER = vector["container"]
OWN = vector["inputs"]["password"].encode()
HIDDEN = b"synthetic hidden wallet test password"
ENTER, LEAVE, CLEAR = b"\x1b[?1049h", b"\x1b[?1049l", b"\x1b[2J\x1b[H"

pid, fd = pty.fork()
if pid == 0:
    os.environ["NO_COLOR"] = "1"
    os.execv(BINARY, ["mhfe", "wallets"])
out = b""
def until(needle, limit, since=None):
    global out
    start = len(out) if since is None else since
    end = time.time() + limit
    while time.time() < end:
        if needle in out[start:]:
            return out.index(needle, start)
        if select.select([fd], [], [], 0.2)[0]:
            try:
                out += os.read(fd, 65536)
            except OSError:
                break
    sys.exit(f"timed out waiting for {needle!r}; last output: {out[-600:]!r}")

until(b"Esc cancels", 30); os.write(fd, b"\r")                        # settings: the defaults
until(b"original: ", 1200); os.write(fd, CONTAINER.encode() + b"\r")  # after the self-test
until(b"if it has none", 30); os.write(fd, b"\r")                     # no BIP39 passphrase
until(b"Password: ", 30); os.write(fd, OWN + b"\r")
until(b"Repeat the password: ", 30); os.write(fd, OWN + b"\r")
refused = until(b"Choose another.", 1200)                             # rule I29
again = until(b"Password: ", 30, since=refused)
assert CLEAR not in out[refused:again], "the refusal was cleared before it could be read"
os.write(fd, HIDDEN + b"\r")
until(b"Repeat the password: ", 30); os.write(fd, HIDDEN + b"\r")
until(b"Open another wallet?", 1200)
until(b"Esc cancels", 30, since=len(out) - 2000)
private = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", out).decode()
box = private[private.rfind("Wallet 1, 24 words"):]
words = re.findall(r"\d+\.\s+([a-z]+)", box)[:24]
os.write(fd, b"2")                                                    # no other wallet
until(b"More: ", 30)
time.sleep(0.5)
try:
    while select.select([fd], [], [], 0.3)[0]:
        out += os.read(fd, 65536)
except OSError:
    pass
_, status = os.waitpid(pid, 0)

# The main screen: everything outside the private screens.
main, rest = b"", out
while ENTER in rest:
    before, rest = rest.split(ENTER, 1)
    main += before
    rest = rest.split(LEAVE, 1)[1] if LEAVE in rest else b""
main += rest
main_text = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", main).replace(b"\r", b"").decode()
print(main_text[main_text.rfind("Self-test") - 2:])
print("exit status:", os.waitstatus_to_exitcode(status))
assert os.waitstatus_to_exitcode(status) == 0
assert len(words) == 24, words
for secret in ("Wallet 1", " ".join(words), "Open another wallet"):
    assert secret not in main_text, f"the main screen shows {secret!r}"
print("OK: wallet, its question and its number only on the private screen; refusal readable")
result = subprocess.run([BINARY, "decrypt", "--stdin"], input=f"{CONTAINER}\n{HIDDEN.decode()}\n",
                        capture_output=True, text=True, timeout=1200)
recovered = result.stdout.strip().split()
print("decrypt with the hidden password:", recovered[:2], "...")
assert recovered[:2] == ["24", "unverified"] and recovered[2:] == words, recovered
print("OK: the shown wallet is what recovery with that password gives, unverified")
