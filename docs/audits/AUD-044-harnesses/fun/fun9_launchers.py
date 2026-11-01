#!/usr/bin/env python3
"""AUD-044 fun probe: the two fast-mode launchers side by side on 127.0.0.1, in a folder of their own
under tmp/aud044/fun/serve: the Rust `mhfe serve` of the release program and the Python launcher of
this checkout. The page is a public stub. Nothing leaves the computer."""
import hashlib, os, re, resource, shutil, socket, stat, subprocess, sys, time

ROOT = "../tmp/aud044/fun/serve"
RUST = "../tmp/aud044/target/release/mhfe"
PY = "packaging/mhfe-fast-mode.py"
page = b"<!doctype html><title>stub</title>\n"
digest = hashlib.sha256(page).hexdigest()

def fresh(checksum=None):
    d = os.path.join(ROOT, "site")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    with open(os.path.join(d, "page.html"), "wb") as f:
        f.write(page)
    p = os.path.join(d, "mhfe-fast-mode.sha256")
    with open(p, "wb") as f:
        f.write(checksum if checksum is not None else f"{digest}  page.html\n".encode())
    return d

def start(which, d, limit=None):
    def prepare():
        if limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, (limit, limit))
    if which == "rust":
        args = [RUST, "serve", os.path.join(d, "page.html"), "--no-browser"]
    else:
        args = ["python3", "-I", PY, os.path.join(d, "page.html"), "--no-browser"]
    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, preexec_fn=prepare)

def address(proc, seconds=6):
    end = time.time() + seconds
    text = ""
    os.set_blocking(proc.stdout.fileno(), False)
    while time.time() < end:
        try:
            chunk = os.read(proc.stdout.fileno(), 65536).decode("utf-8", "replace")
        except BlockingIOError:
            chunk = ""
        if chunk:
            text += chunk
        m = re.search(r"http://127\.0\.0\.1:(\d+)", text)
        if m:
            return int(m.group(1)), text
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    return None, text

def ask(port, raw):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.sendall(raw)
    s.settimeout(3)
    data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            data += c
    except OSError:
        pass
    s.close()
    return data.split(b"\r\n")[0].decode("latin-1") if data else "(no answer)"

def row(title):
    print(f"== {title}", flush=True)

# AUD-024-FUN006: a lone CR before the digest.
row("checksum line after a lone CR and spaces")
for which in ("rust", "python"):
    d = fresh(f"  \r{digest}  page.html\n".encode())
    proc = start(which, d)
    port, text = address(proc, 3)
    print(which, "served" if port else "refused:", "" if port else text.strip().splitlines()[-1][:100], flush=True)
    proc.kill()

# AUD-024-FUN005: blank lines, a FIFO, /dev/zero.
row("one valid line and 8 MiB of blank lines")
for which in ("rust", "python"):
    d = fresh(f"{digest}  page.html\n".encode() + b"\n" * (8 << 20))
    proc = start(which, d)
    port, text = address(proc, 4)
    print(which, "served" if port else "refused", flush=True)
    proc.kill()
row("checksum file is a FIFO")
for which in ("rust", "python"):
    d = fresh()
    p = os.path.join(d, "mhfe-fast-mode.sha256")
    os.remove(p)
    os.mkfifo(p)
    proc = start(which, d)
    port, text = address(proc, 3)
    print(which, "still waiting after 3 s" if proc.poll() is None else f"ended {proc.returncode}: {text.strip()[-90:]}", flush=True)
    proc.kill()
row("page links to /dev/zero, memory limit 300 MiB")
for which in ("rust", "python"):
    d = fresh()
    p = os.path.join(d, "page.html")
    os.remove(p)
    os.symlink("/dev/zero", p)
    def prepare():
        resource.setrlimit(resource.RLIMIT_AS, (300 << 20, 300 << 20))
    args = [RUST, "serve", p, "--no-browser"] if which == "rust" else ["python3", "-I", PY, p, "--no-browser"]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=30, preexec_fn=prepare)
    print(which, "exit", proc.returncode, (proc.stderr or proc.stdout).strip()[-150:].replace("\n", " | "), flush=True)

# AUD-024-FUN007: request heads.
heads = {
    "Host name with U+001C after it": lambda h: f"GET / HTTP/1.1\r\nHost\x1c: {h}\r\n\r\n".encode(),
    "Host value with U+001F around it": lambda h: f"GET / HTTP/1.1\r\nHost: \x1f{h}\x1f\r\n\r\n".encode(),
    "request line ending in two CRs": lambda h: f"GET / HTTP/1.1\r\r\nHost: {h}\r\n\r\n".encode(),
    "UTF-8 header value": lambda h: f"GET / HTTP/1.1\r\nHost: {h}\r\nX-A: é\r\n\r\n".encode(),
    "Host only after a bare-LF end": lambda h: f"GET / HTTP/1.1\n\nHost: {h}\r\n\r\n".encode(),
}
row("request heads")
d = fresh()
ports = {}
procs = {}
for which in ("rust", "python"):
    procs[which] = start(which, d)
    ports[which], _ = address(procs[which])
for title, head in heads.items():
    answers = {w: ask(ports[w], head(f"127.0.0.1:{ports[w]}")) for w in ports}
    print(f"{title}: rust {answers['rust']!r}, python {answers['python']!r}", flush=True)
for p in procs.values():
    p.kill()

# AUD-023-FUN003: accept() fails with EMFILE.
row("accept() refused for lack of descriptors, limit 12")
for which in ("rust", "python"):
    d = fresh()
    proc = start(which, d, limit=12)
    port, text = address(proc)
    if not port:
        print(which, "did not start:", text.strip()[-100:], flush=True)
        proc.kill()
        continue
    conns = []
    for _ in range(14):
        try:
            conns.append(socket.create_connection(("127.0.0.1", port), timeout=1))
        except OSError:
            break
        time.sleep(0.05)
    time.sleep(1.5)
    state = "running" if proc.poll() is None else f"ended with exit {proc.returncode}"
    print(which, state, flush=True)
    for c in conns:
        c.close()
    time.sleep(0.5)
    if proc.poll() is None:
        print(which, "answers after the descriptors are back:", ask(port, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()), flush=True)
    proc.kill()
