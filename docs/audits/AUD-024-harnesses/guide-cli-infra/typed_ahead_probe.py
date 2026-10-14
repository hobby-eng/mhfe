"""AUD-024 guide-cli-infra probe of AUD-023-UI003: `mhfe password` in a pseudo-terminal with an
Enter typed at once, during the checks at start. The screen that shows the password once must
stay until a key pressed after it appeared: the probe checks that the process is still waiting
1.5 s after the typed-ahead Enter, then sends Enter and expects it to end with exit 0."""
import os, pty, select, signal, sys, time
mhfe = sys.argv[1]
env = dict(os.environ, TERM="xterm-256color")
pid, fd = pty.fork()
if pid == 0:
    os.execve(mhfe, [mhfe, "password"], env)
os.write(fd, b"\r")  # typed ahead, before the screen appears
out = b""
end = time.time() + 1.5
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.1)
    if r:
        try:
            out += os.read(fd, 65536)
        except OSError:
            break
done, status = os.waitpid(pid, os.WNOHANG)
still_waiting = done == 0
print("shown the wait:", b"clears this screen" in out or b"Enter" in out)
print("still waiting 1.5 s after the typed-ahead Enter:", still_waiting)
if still_waiting:
    os.write(fd, b"\r")
    time.sleep(1.0)
    done, status = os.waitpid(pid, os.WNOHANG)
    if done == 0:
        os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
        print("did not end on a later Enter")
        sys.exit(1)
    print("ended on a later Enter, exit", os.waitstatus_to_exitcode(status))
sys.exit(0 if still_waiting else 1)
