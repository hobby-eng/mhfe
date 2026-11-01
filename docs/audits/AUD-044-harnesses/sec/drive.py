#!/usr/bin/env python3
"""AUD-044 SEC probe: drives mhfe in a pseudo-terminal, with memscan.so loaded, through a scenario
of prompts, and leaves what the program printed and what memscan logged next to each other.

    drive.py <scenario> <mhfe program> <memscan.so> <work folder>

Public test data only. Nothing here changes the program or its protections.
"""
import fcntl
import hashlib
import hmac
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from collections import Counter

# A published BIP39 vector: 24 words whose entropy is no pattern.
PHRASE_24 = (
    "hamster diagram private dutch cause delay private meat slide toddler razor book "
    "happy fancy gospel tennis maple dilemma loan word shrug inflict delay length"
)
PHRASE_12 = "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
# The public test phrase of BIP84, with its first receiving address.
PHRASE_ZERO = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
ADDRESS_ZERO = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
# A valid 24-word phrase, used as a container where nothing is decrypted.
ZERO_CONTAINER = " ".join(["abandon"] * 23 + ["art"])
PASSWORD = "audit-public-password-044"
NEW_PASSWORD = "audit-public-new-password-044"
# Six words of the EFF list; the sixth is no check word of the other five.
EFF_PASSWORD = "zookeeper zoologist zoning zombie zodiac zipfile"
# The chosen word of a new phrase, in capitals: the list words of a hint are in lower case, so a
# hit of this text is a copy of what was typed.
CHOSEN_WORD = "HAMSTER"
PASSPHRASE = "audit-public-passphrase-044"
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-B]")


def seed_of(phrase, passphrase=""):
    return hashlib.pbkdf2_hmac(
        "sha512", phrase.encode(), b"mnemonic" + passphrase.encode(), 2048
    )


def master_of(seed):
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return digest[:32], digest[32:]


# secp256k1, for the public key of a child key that is not hardened.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (slope * slope - a[0] - b[0]) % P
    return (x, (slope * (a[0] - x) - a[1]) % P)


def public_key(key):
    point, base, k = None, G, int.from_bytes(key, "big")
    while k:
        if k & 1:
            point = add(point, base)
        base = add(base, base)
        k >>= 1
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def child(key, chain, index):
    if index >= 2**31:
        data = b"\0" + key + index.to_bytes(4, "big")
    else:
        data = public_key(key) + index.to_bytes(4, "big")
    digest = hmac.new(chain, data, hashlib.sha512).digest()
    sum_ = (int.from_bytes(digest[:32], "big") + int.from_bytes(key, "big")) % N
    return sum_.to_bytes(32, "big"), digest[32:]


def bip84_needles(phrase, name):
    """The master key and the private keys and chain codes of m/84'/0'/0'/0/0."""
    seed = seed_of(phrase)
    key, chain = master_of(seed)
    rows = [(name + "-seed", seed[:32]), (name + "-master-key", key), (name + "-chain-code", chain)]
    # The same key as a scalar: four 64-bit limbs, the lowest first, on a little-endian computer.
    rows.append((name + "-master-scalar", key[::-1]))
    for step, index in enumerate((84 + 2**31, 2**31, 2**31, 0, 0)):
        key, chain = child(key, chain, index)
        rows.append(("%s-child%d-key" % (name, step), key))
        rows.append(("%s-child%d-scalar" % (name, step), key[::-1]))
        rows.append(("%s-child%d-chain" % (name, step), chain))
    return rows


def bech32_address(program):
    """The P2WPKH address of a 20-byte program (BIP173), for a phrase with a passphrase."""
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def polymod(values):
        check = 1
        for value in values:
            top = check >> 25
            check = (check & 0x1FFFFFF) << 5 ^ value
            for bit, generator in enumerate(
                (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
            ):
                check ^= generator if top >> bit & 1 else 0
        return check

    bits, count, data = 0, 0, [0]
    for byte in program:
        bits = bits << 8 | byte
        count += 8
        while count >= 5:
            count -= 5
            data.append(bits >> count & 31)
    if count:
        data.append(bits << (5 - count) & 31)
    prefix = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    remainder = polymod(prefix + data + [0] * 6) ^ 1
    data += [remainder >> 5 * (5 - i) & 31 for i in range(6)]
    return "bc1" + "".join(charset[value] for value in data)


def first_address(phrase, passphrase):
    key, chain = master_of(seed_of(phrase, passphrase))
    for index in (84 + 2**31, 2**31, 2**31, 0, 0):
        key, chain = child(key, chain, index)
    digest = hashlib.new("ripemd160", hashlib.sha256(public_key(key)).digest()).digest()
    return bech32_address(digest)


def needles():
    rows = [("password", PASSWORD.encode()), ("passphrase", PASSPHRASE.encode())]
    rows.append(("new-password", NEW_PASSWORD.encode()))
    rows.append(("chosen-word", CHOSEN_WORD.encode()))
    rows.append(("eff-password", EFF_PASSWORD.encode()))
    rows += bip84_needles(PHRASE_ZERO, "p0")
    for word in EFF_PASSWORD.split():
        rows.append(("eff-" + word, word.encode()))
    rows.append(("password-hint-word", b"audit"))
    for name, phrase in (("p24", PHRASE_24), ("p12", PHRASE_12)):
        rows.append((name + "-whole", phrase.encode()))
        rows.append((name + "-first3", " ".join(phrase.split()[:3]).encode()))
        for passphrase, tag in (("", ""), (PASSPHRASE, "+pp")):
            seed = seed_of(phrase, passphrase)
            key, chain = master_of(seed)
            rows.append((name + "-seed" + tag, seed[:32]))
            rows.append((name + "-master-key" + tag, key))
            rows.append((name + "-chain-code" + tag, chain))
    for word in sorted(set(PHRASE_24.split())):
        rows.append(("word-" + word, word.encode()))
    return rows


class Terminal:
    def __init__(self, argv, work, environment):
        self.log = os.path.join(work, "memscan.log")
        self.transcript = open(os.path.join(work, "transcript.txt"), "w", encoding="utf-8")
        self.seen = ""
        self.raw = None
        pid, fd = pty.fork()
        if pid == 0:
            log = os.open(self.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.dup2(log, 9)
            os.execve(argv[0], argv, environment)
        self.pid, self.fd = pid, fd
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))

    def pump(self, seconds):
        end = time.time() + seconds
        while True:
            left = end - time.time()
            if left <= 0:
                return
            ready, _, _ = select.select([self.fd], [], [], left)
            if ready:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    return
                if not data:
                    return
                if self.raw:
                    self.raw.write(data)
                    self.raw.flush()
                text = ANSI.sub("", data.decode("utf-8", "replace"))
                self.seen += text
                self.transcript.write(text)
                self.transcript.flush()

    def expect(self, text, timeout=60):
        end = time.time() + timeout
        while text not in self.seen:
            if time.time() > end:
                self.transcript.write("\n[timeout waiting for %r]\n" % text)
                self.transcript.flush()
                raise SystemExit("timeout waiting for %r; see transcript" % text)
            self.pump(0.05)
        self.seen = self.seen.split(text, 1)[1]

    def type(self, text, delay=0.002):
        for byte in text.encode():
            os.write(self.fd, bytes([byte]))
            self.pump(delay)

    def enter(self):
        os.write(self.fd, b"\r")
        self.pump(0.05)

    def scan(self, label):
        with open(self.log, "a", encoding="ascii") as log:
            log.write("=== scan at: %s\n" % label)
        os.kill(self.pid, signal.SIGUSR1)
        self.pump(0.6)

    def note(self, label):
        with open(self.log, "a", encoding="ascii") as log:
            log.write("=== %s\n" % label)

    def control_c(self):
        os.write(self.fd, b"\x03")
        self.pump(0.3)

    def wait(self):
        self.pump(0.5)
        _, status = os.waitpid(self.pid, 0)
        return status


def encrypt_until_password(t):
    """The phrase of 24 words, typed key by key on the private screen, then the password."""
    t.expect("Original seed phrase")
    t.note("typing the phrase")
    t.type(PHRASE_24)
    t.scan("end of the phrase line, not yet entered")
    t.enter()


SCENARIOS = {}


def scenario(function):
    SCENARIOS[function.__name__] = function
    return function


@scenario
def typed_phrase(program, work, environment):
    """`mhfe encrypt` up to the second password prompt, stopped by Ctrl+C before any round."""
    t = Terminal([program, "encrypt", "--pim", "0", "--mem", "0", "--new-password", "own"], work,
                 environment)
    encrypt_until_password(t)
    t.pump(1.0)
    t.scan("after the phrase was entered, at the next question")
    t.note("transcript so far in transcript.txt")
    return t


@scenario
def typed_phrase_control(program, work, environment):
    """The same, with another phrase typed: what the words of PHRASE_24 are without being typed."""
    t = Terminal([program, "encrypt", "--pim", "0", "--mem", "0", "--new-password", "own"], work,
                 environment)
    t.expect("Original seed phrase")
    t.type(PHRASE_12)
    t.scan("end of the phrase line, not yet entered")
    t.enter()
    t.pump(1.0)
    t.scan("after the phrase was entered, at the next question")
    return t


class Finished:
    """What main() expects of a scenario that ran its program to the end by itself."""

    pid = None


def script(program, work, environment, arguments, lines):
    """Runs a command with --stdin, one answer per line, and returns its standard output."""
    log = os.path.join(work, "memscan.log")
    descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with open(log, "a", encoding="ascii") as note:
        note.write("=== script: %s\n" % " ".join(arguments))
    done = subprocess.run(
        [program] + arguments,
        input="".join(line + "\n" for line in lines).encode(),
        capture_output=True,
        env=environment,
        pass_fds=(9,) if os.dup2(descriptor, 9) == 9 else (),
        check=False,
    )
    os.close(9)
    os.close(descriptor)
    with open(os.path.join(work, "outputs.txt"), "ab") as out:
        out.write(b"--- " + " ".join(arguments).encode() + b" exit %d\n" % done.returncode)
        out.write(done.stdout + done.stderr)
    return done.stdout.decode()


@scenario
def script_flows(program, work, environment):
    """--stdin flows on the reduced-cost program: what each command leaves when it ends."""
    os.makedirs(work, exist_ok=True)
    settings = ["--pim", "0", "--mem", "0"]
    container = script(program, work, environment, ["encrypt", "--stdin"] + settings,
                       [PHRASE_24, PASSWORD, PASSWORD]).strip()
    script(program, work, environment, ["decrypt", "--stdin"] + settings, [container, PASSWORD])
    script(program, work, environment,
           ["decrypt", "--stdin", "--passphrase-used", "yes"] + settings,
           [container, PASSWORD, PASSPHRASE])
    return Finished()


@scenario
def script_check(program, work, environment):
    """A rehearsal against an address: the seed and every key of the path, what is left of them."""
    settings = ["--pim", "0", "--mem", "0"]
    container = script(program, work, environment, ["encrypt", "--stdin"] + settings,
                       [PHRASE_ZERO, PASSWORD, PASSWORD]).strip()
    script(program, work, environment, ["check", "--stdin", "--address"] + settings,
           [container, PASSWORD, ADDRESS_ZERO, ""])
    return Finished()


def make_container(program, work, environment, phrase):
    return script(program, work, environment, ["encrypt", "--stdin", "--pim", "0", "--mem", "0"],
                  [phrase, PASSWORD, PASSWORD]).strip()


@scenario
def decrypt_terminal(program, work, environment):
    """A recovery at a terminal: the phrase and its fingerprint on the private screen."""
    container = make_container(program, work, environment, PHRASE_ZERO)
    t = Terminal([program, "decrypt", "--pim", "0", "--mem", "0"], work, environment)
    t.expect("Container, 24 words")
    t.type(container)
    t.enter()
    t.expect("Container password")
    t.type(PASSWORD)
    t.enter()
    t.expect("Write it down now")
    t.pump(0.5)
    t.scan("the recovered phrase on the screen, waiting for Enter")
    t.enter()
    t.pump(0.5)
    return t


@scenario
def rekey_with_passphrase(program, work, environment):
    """A rekey confirmed by an address of a wallet with a BIP39 passphrase."""
    container = make_container(program, work, environment, PHRASE_ZERO)
    t = Terminal([program, "rekey", "--pim", "0", "--mem", "0", "--new-pim", "0", "--new-mem", "0",
                  "--words", "auto", "--confirm", "address", "--passphrase-used", "yes",
                  "--repair-words", "0", "--new-password", "own"], work, environment)
    t.expect("Container, 24 words")
    t.type(container)
    t.enter()
    t.expect("Old container password")
    t.type(PASSWORD)
    t.enter()
    t.expect("choose")
    t.pump(0.3)
    t.enter()  # Bitcoin, the first coin of the list
    t.expect("address")
    t.pump(0.3)
    t.type(first_address(PHRASE_ZERO, PASSPHRASE))
    t.enter()
    t.expect("BIP39 passphrase of")
    t.type(PASSPHRASE)
    t.enter()
    t.expect("New container password", 120)
    t.pump(0.5)
    t.scan("the prompt for the new password, the recovery confirmed by the address")
    t.type(NEW_PASSWORD)
    t.enter()
    t.expect("Repeat the new container password")
    t.type(NEW_PASSWORD)
    t.enter()
    t.expect("Write it down now", 120)
    t.pump(0.5)
    t.scan("the new container on the screen, waiting for Enter")
    t.enter()
    t.pump(0.5)
    return t


@scenario
def new_with_chosen_word(program, work, environment):
    """`mhfe new` up to the word never to use: where the chosen word waits meanwhile."""
    t = Terminal([program, "new", "--pim", "0", "--mem", "0", "--repair-words", "0",
                  "--new-password", "own"], work, environment)
    t.expect("BIP39 passphrase of the new wallet")
    t.type(PASSPHRASE)
    t.enter()
    t.expect("Repeat the passphrase")
    t.type(PASSPHRASE)
    t.enter()
    t.expect("Do you want a check")
    t.pump(0.3)
    t.type("1")
    t.expect("Do you want to choose a word")
    t.pump(0.3)
    t.type("2")
    t.expect("Chosen word")
    t.type(CHOSEN_WORD)
    t.enter()
    t.expect("Its position")
    t.enter()
    t.expect("Word never to use")
    t.pump(0.3)
    t.scan("the prompt for the word never to use")
    t.enter()
    t.pump(0.5)
    t.scan("after the wishes, the next question")
    return t


@scenario
def password_with_hints(program, work, environment):
    """A password of EFF words typed on the private screen, as far as the repetition."""
    t = Terminal([program, "encrypt", "--pim", "0", "--mem", "0", "--repair-words", "0",
                  "--new-password", "own"], work, environment)
    t.expect("Original seed phrase")
    t.type(PHRASE_24)
    t.enter()
    t.expect("Container password")
    t.note("typing the password")
    t.type(EFF_PASSWORD)
    t.enter()
    t.expect("Repeat the container password")
    t.pump(0.3)
    t.scan("the repetition of the password")
    return t


@scenario
def password_with_hints_control(program, work, environment):
    """The same with another password: what the EFF words are without being typed."""
    t = Terminal([program, "encrypt", "--pim", "0", "--mem", "0", "--repair-words", "0",
                  "--new-password", "own"], work, environment)
    t.expect("Original seed phrase")
    t.type(PHRASE_24)
    t.enter()
    t.expect("Container password")
    t.note("typing the password")
    t.type(PASSWORD)
    t.enter()
    t.expect("Repeat the container password")
    t.pump(0.3)
    t.scan("the repetition of the password")
    return t


@scenario
def check_word_offer(program, work, environment):
    """Six EFF words whose check word does not fit: the offer on the private screen, a real
    prompt before any round."""
    t = Terminal([program, "decrypt", "--pim", "0", "--mem", "0"], work, environment)
    t.expect("Container, 24 words")
    t.type(ZERO_CONTAINER)
    t.enter()
    t.expect("Container password")
    t.note("typing the password")
    t.type(EFF_PASSWORD)
    t.note("password typed, the hints end here")
    t.enter()
    t.expect("Repair the password")
    t.pump(0.5)
    t.type("\x1b[B")  # the arrow key: the list is drawn again
    t.pump(0.3)
    t.scan("the offer of the check word on the screen")
    return t


@scenario
def dumb_terminal(program, work, environment):
    """TERM=dumb, where no private screen is possible: what the terminal shows of a container
    typed for a recovery. The stream is kept raw, to see whether the alternate screen is used."""
    environment = dict(environment, TERM="dumb")
    t = Terminal([program, "decrypt", "--pim", "0", "--mem", "0"], work, environment)
    t.raw = open(os.path.join(work, "raw.txt"), "wb")
    t.expect("Container, 24 words")
    t.type(ZERO_CONTAINER)
    t.enter()
    t.expect("Container password")
    return t


@scenario
def stdin_at_terminal(program, work, environment):
    """--stdin with standard input at a terminal: a person answers the script's lines. Does the
    terminal echo the phrase and the password onto the main screen?"""
    t = Terminal([program, "encrypt", "--stdin", "--pim", "0", "--mem", "0"], work, environment)
    t.raw = open(os.path.join(work, "raw.txt"), "wb")
    t.pump(1.0)
    t.type(PHRASE_24)
    t.enter()
    t.pump(0.3)
    t.type(PASSWORD)
    t.enter()
    t.pump(0.5)
    return t


@scenario
def hidden_wallets(program, work, environment):
    """`mhfe wallets`: two wallets opened, with the main wallet's passphrase; what lies in ordinary
    memory while a wallet is on the screen."""
    container = make_container(program, work, environment, PHRASE_24)
    t = Terminal([program, "wallets", "--pim", "0", "--mem", "0"], work, environment)
    t.expect("Container, 24 words")
    t.type(container)
    t.enter()
    t.expect("BIP39 passphrase of the main wallet")
    t.type(PASSPHRASE)
    t.enter()
    t.expect("Hidden wallet password")
    t.type(NEW_PASSWORD)
    t.enter()
    t.expect("Repeat the hidden wallet password")
    t.type(NEW_PASSWORD)
    t.enter()
    t.expect("Open another wallet", 120)
    t.pump(0.5)
    t.scan("a hidden wallet on the screen")
    return t


def main():
    name, program, shim, work = sys.argv[1:5]
    os.makedirs(work, exist_ok=True)
    needle_file = os.path.join(work, "needles.txt")
    with open(needle_file, "w", encoding="ascii") as file:
        for label, value in needles():
            file.write("%s %s\n" % (label, value.hex()))
    log = os.path.join(work, "memscan.log")
    if os.path.exists(log):
        os.remove(log)
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": work,
        "TERM": "xterm-256color",
        "LANG": "C.UTF-8",
        "LD_PRELOAD": shim,
        "MEMSCAN_NEEDLES": needle_file,
    }
    t = SCENARIOS[name](program, work, environment)
    if t.pid is not None:
        t.control_c()
        finished, status = os.waitpid(t.pid, os.WNOHANG)
        print("status after Ctrl+C:", (finished, status))
        if not finished:
            os.kill(t.pid, signal.SIGKILL)
            os.waitpid(t.pid, 0)
    print("transcript:", os.path.join(work, "transcript.txt"))
    print("log:", log)


if __name__ == "__main__":
    main()
