"""AUD-024 probe (AUD-023-FUN003): `mhfe serve --no-browser` under prlimit --nofile=4 (soft 4,
hard 1024) on loopback. Phase 1: three connections it cannot accept, then 2 s; the processor time
it took must stay small (no spin). Phase 2: the soft limit is raised to 64 with prlimit --pid; a
GET / must then return 200 and the page. Exit 0 when both hold, 1 otherwise."""
import hashlib, os, re, socket, subprocess, sys, tempfile, time
from pathlib import Path

program = sys.argv[1]
PAGE = b"<!doctype html><title>public test page</title>"
tick = os.sysconf("SC_CLK_TCK")
failures = []
with tempfile.TemporaryDirectory() as folder:
    page = Path(folder) / "tool.html"
    page.write_bytes(PAGE)
    (Path(folder) / "mhfe-fast-mode.sha256").write_text(hashlib.sha256(PAGE).hexdigest() + "  tool.html\n")
    env = {k: v for k, v in os.environ.items() if k not in ("CI", "CLICOLOR_FORCE")}
    env["NO_COLOR"] = "1"
    proc = subprocess.Popen(["prlimit", "--nofile=4:1024", program, "serve", "--no-browser", str(page)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
    lines = []
    for raw in proc.stderr:
        lines.append(raw.decode(errors="replace").rstrip("\n"))
        if "Fast mode is running" in lines[-1]:
            break
    print("stderr until running:", lines)
    port = int(re.search(r"127\.0\.0\.1:(\d+)", "\n".join(lines)).group(1))
    for i in range(3):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1)
            s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % port)
            s.settimeout(1)
            try:
                print(f"phase 1 request {i}: reply {s.recv(64)!r}")
            except OSError as e:
                print(f"phase 1 request {i}: {type(e).__name__} {e}")
            s.close()
        except OSError as e:
            print(f"phase 1 connect {i}: {type(e).__name__} {e}")
    time.sleep(2)
    fields = Path(f"/proc/{proc.pid}/stat").read_text().rsplit(")", 1)[1].split()
    ticks = int(fields[11]) + int(fields[12])
    state = fields[0]
    print(f"phase 1: process state {state}, cpu ticks {ticks} ({ticks/tick:.2f} s) over ~5 s")
    if ticks / tick >= 0.5:
        failures.append("spins")
    # serve is the child of prlimit (prlimit execs, so same pid)
    r = subprocess.run(["prlimit", "--pid", str(proc.pid), "--nofile=64:1024"], capture_output=True, text=True)
    print("raise limit:", r.returncode, r.stderr.strip())
    time.sleep(0.5)
    body = b""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n" % port)
        s.settimeout(3)
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            body += chunk
        s.close()
    except OSError as e:
        print("phase 2:", type(e).__name__, e)
    print("phase 2 reply head:", body.split(b"\r\n", 1)[0])
    if not body.startswith(b"HTTP/1.1 200") or not body.endswith(PAGE):
        failures.append("does not serve once descriptors are available")
    proc.terminate(); proc.wait(10)
print("FAIL: " + "; ".join(failures) if failures else "PASS: no spin, and it serves once descriptors are available")
sys.exit(1 if failures else 0)
