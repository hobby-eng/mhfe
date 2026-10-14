#!/usr/bin/env python3
"""AUD-024 verifier probe (scratch): line refusals at a terminal and from a script.

Terminal runs (pseudo-terminal) of `mhfe encrypt --pim 0 --mem 0 --same-length no
--new-password own --repair-words 0`:
  T1 first prompt (original seed phrase): byte 0xff, Enter
  T2 first prompt: 8,193 letters 'a' (one over LINE_CAPACITY), no Enter
  T3 first prompt: the public 12-word test phrase (accepted), then at the password prompt the
     byte 0xff and Enter: does the command end, discarding the accepted phrase?
  T4 control: as T3, but an empty line at the password prompt (Password::new refuses it)
Script runs with --stdin:
  S1 phrase line 0xff
  S2 public phrase, then password line 0xff (the library's InvalidPasswordUtf8 is exit 2)
  S3 phrase line of 8,192 'a' + newline (over the limit: control for exit 2)
No password is ever accepted, so no encryption round runs.
"""
import os, pty, select, signal, subprocess, sys, time

PHRASE = b"abandon " * 11 + b"about"
ARGS = ["encrypt", "--pim", "0", "--mem", "0", "--same-length", "no",
        "--new-password", "own", "--repair-words", "0"]


def read_for(fd, seconds):
    data, end = b"", time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
    return data


def wait_for(fd, seen, needle, seconds=30):
    end = time.time() + seconds
    while needle not in seen and time.time() < end:
        seen += read_for(fd, 0.2)
    return seen


def terminal(label, steps):
    binary = sys.argv[1]
    master, slave = pty.openpty()
    env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "CLICOLOR_FORCE")}
    env["TERM"] = "xterm-256color"
    p = subprocess.Popen([binary, *ARGS], stdin=slave, stdout=slave, stderr=slave, env=env,
                         start_new_session=True)
    os.close(slave)
    seen = b""
    counts = []
    for prompt, answer in steps:
        seen = wait_for(master, seen, prompt)
        before = seen.count(prompt)
        for i in range(0, len(answer), 256):
            os.write(master, answer[i:i + 256])
            seen += read_for(master, 0.02)
        seen += read_for(master, 2.0)
        counts.append((prompt.decode(), before, seen.count(prompt)))
    status = p.poll()
    text = seen.decode("utf-8", "replace").replace("\r", "\n")
    errors = [l.strip() for l in text.split("\n") if "Error" in l or "again" in l or "Choose another" in l or "choose another" in l]
    print(f"{label}: prompt counts (prompt, before answer, after) {counts}; "
          f"running: {status is None}; exit: {status}; last messages: {errors[-2:]}")
    if status is None:
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=10)
    os.close(master)
    return status


def script(label, data):
    env = {**os.environ, "NO_COLOR": "1"}
    r = subprocess.run([sys.argv[1], "encrypt", "--stdin", "--pim", "0", "--mem", "0",
                        "--same-length", "no"], input=data, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, env=env)
    last = r.stderr.decode("utf-8", "replace").strip().splitlines()[-1:]
    print(f"{label}: exit {r.returncode}; last line: {last}")
    return r.returncode


P1, P2 = b"Original seed phrase", b"Container password"
t1 = terminal("T1 first prompt, 0xff", [(P1, b"\xff\r")])
t2 = terminal("T2 first prompt, 8,193 bytes", [(P1, b"a" * 8193)])
t3 = terminal("T3 password prompt after accepted phrase, 0xff", [(P1, PHRASE + b"\r"), (P2, b"\xff\r")])
t4 = terminal("T4 control: password prompt, empty line", [(P1, PHRASE + b"\r"), (P2, b"\r")])
s1 = script("S1 --stdin phrase line 0xff", b"\xff\n")
s2 = script("S2 --stdin password line 0xff", PHRASE + b"\n\xff\n\xff\n")
s3 = script("S3 --stdin phrase line 8,192 bytes (control)", b"a" * 8192 + b"\n")
defect = t1 is not None and t2 is not None and t3 is not None and t4 is None and s1 == 1 and s2 == 1 and s3 == 2
print("DEFECT REPRODUCED" if defect else "DEFECT NOT REPRODUCED (see lines above)")
sys.exit(1 if defect else 0)
