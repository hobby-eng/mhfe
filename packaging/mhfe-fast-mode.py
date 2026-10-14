#!/usr/bin/env python3
"""Fast mode for an MHFE browser tool, for computers with Python but without the mhfe program.

A browser runs the four Argon2 lanes of MHFE in parallel only on a cross-origin isolated page, and
a page opened as a file is never isolated. This script serves one HTML file from 127.0.0.1 with
the headers that make it isolated, and opens it in the browser. It does what `mhfe serve` does,
with the same limits, and never receives or processes a secret: the page does all the work.

It serves a page only when the checksum file mhfe-fast-mode.sha256 lies next to it and names it
with a matching SHA-256; otherwise it refuses with a message and serves nothing.

Usage:
    python3 mhfe-fast-mode.py              serve the page named in the mhfe-fast-mode.sha256 next
                                           to this script, as a double-click does
    python3 mhfe-fast-mode.py tool.html    serve tool.html; mhfe-fast-mode.sha256 must lie next
                                           to it and name it
    --no-browser                           print the address instead of opening the browser

Needs Python 3.8 or later and nothing else. It answers GET and HEAD of "/" only, checks the Host
header against DNS rebinding, ignores request bodies and logs nothing.
"""

import argparse
import hashlib
import os
import socket
import sys
import textwrap
import threading
import time
import unicodedata
import webbrowser

# The same limits as `mhfe serve` (src/bin/mhfe/serve.rs).
# Longest request head accepted; real browsers send far less.
MAX_REQUEST_HEAD = 16 * 1024
# Seconds a client has for its whole request head. A limit on each read alone would let a client
# that sends one byte at a time keep its connection open for ever.
REQUEST_DEADLINE = 10.0
# Seconds for sending the whole answer. Since Python 3.5 a socket timeout limits the total time
# of sendall, not each piece it sends, so a client that reads slowly cannot stretch it.
RESPONSE_DEADLINE = 10.0
# Connections answered at the same time; any further one is closed at once. A browser opens only
# a few, and the cap keeps a flood of connections from starting a thread each.
MAX_CONNECTIONS = 16
# Seconds the listener waits after a connection it could not accept, such as when the process has
# no file descriptor left, so that it does not spin; it then goes on serving (AUD-023-FUN003).
ACCEPT_ERROR_PAUSE = 0.1
# Seconds the listener waits for a connection before it looks again. On Windows a waiting
# accept() does not notice Ctrl+C, so the wait is kept short.
ACCEPT_INTERVAL = 1.0

# Sent with every response. COOP and COEP make the page cross-origin isolated; the others keep it
# from being framed, sniffed, cached or followed by a referrer.
SECURITY_HEADERS = (
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Embedder-Policy", "require-corp"),
    ("Content-Security-Policy", "frame-ancestors 'none'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
)

# The checksum file that must lie next to the page, as for `mhfe serve`. Its name never changes,
# so a tool can ship it beside its HTML file. It holds one line in the format sha256sum writes:
# the SHA-256 of the page, a space, a mode marker (a second space in text mode, "*" in binary
# mode) and the page's file name.
CHECKSUM_FILE = "mhfe-fast-mode.sha256"
# Hexadecimal digits of a SHA-256 digest.
SHA256_HEX_DIGITS = 64

# Exit codes, as the mhfe program uses them.
SUCCESS = 0
INTERNAL_ERROR = 1
INVALID_INPUT = 2

# The terminal style of mhfe (src/bin/mhfe/style.rs), with the standard library alone
# (AUD-023-UI011): a title line, a tick before what went right, "✗ Error:" before a refusal, lines
# of at most 78 columns, and colours only for a terminal that shows them.
TEXT_WIDTH = 78
TICK = "✓"
ERROR_MARK = "✗ Error:"
HEADING, ACCENT, STRONG, MUTED, GOOD, BAD = "1;36", "36", "1", "90", "1;32", "1;31"
# What a fact's label is padded to, as style::fact pads it.
FACT_LABEL_WIDTH = 10
TITLE = "Fast mode"


class Refused(Exception):
    """The file cannot be served; the message says why."""


# The characters Rust's str::trim takes off (Unicode White_Space), so that a checksum line reads
# here as `mhfe serve` reads it (src/bin/mhfe/serve.rs); Python's own strip() also takes U+001C to
# U+001F, which are control characters there.
RUST_WHITESPACE = (
    "\t\n\x0b\x0c\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009"
    "\u200a\u2028\u2029\u202f\u205f\u3000"
)


def colours():
    """Whether standard error shows colours, by the rules mhfe follows (anstream): never on
    Windows, whose console this script cannot switch to them; CLICOLOR_FORCE turns them on, and
    NO_COLOR, TERM=dumb or CLICOLOR=0 off; otherwise only on a terminal."""
    environment = os.environ
    if os.name == "nt":
        return False
    if environment.get("CLICOLOR_FORCE", "0") not in ("", "0"):
        return True
    if environment.get("NO_COLOR", "") != "" or environment.get("TERM") == "dumb":
        return False
    if environment.get("CLICOLOR") == "0":
        return False
    return sys.stderr.isatty()


def paint(style, text):
    """`text` in `style`, an SGR code, where colours are shown."""
    return "\x1b[{}m{}\x1b[0m".format(style, text) if colours() else text


def wrapped(text, width):
    """`text` in lines of at most `width` columns, words never split, as style::wrap does."""
    return textwrap.wrap(text, width, break_long_words=False, break_on_hyphens=False) or [""]


def say(lines):
    for line in lines:
        print(line, file=sys.stderr)


def title():
    """The first line, as every mhfe command starts: "MHFE · Fast mode" after a blank line."""
    say(["", "{} {} {}".format(paint(HEADING, "MHFE"), paint(MUTED, "·"), paint(STRONG, TITLE))])


def ok(text):
    """Something that went right: a tick, the text wrapped and indented under it."""
    lines = wrapped(text, TEXT_WIDTH - 2)
    say(["{} {}".format(paint(GOOD, TICK), lines[0])] + ["  " + line for line in lines[1:]])


def fact(label, value):
    """A labelled value on a line of its own, as style::fact shows it."""
    say(["  {} {}".format(paint(MUTED, label.ljust(FACT_LABEL_WIDTH)), value)])


def error(text):
    """A refusal: "✗ Error:", then the text wrapped under it, as mhfe shows an error."""
    indent = len(ERROR_MARK) + 1
    lines = wrapped(text, TEXT_WIDTH - indent)
    first = "{} {}".format(paint(BAD, ERROR_MARK), lines[0])
    say(["", first] + [" " * indent + line for line in lines[1:]])


# The help, in the sections and words of `mhfe serve --help`.
HELP = """Serve an MHFE browser tool on this computer in fast mode

A browser runs the faster, multi-threaded Argon2 only on a page served with
special headers. This script serves one page from this computer (127.0.0.1)
with those headers and opens it in the browser, as mhfe serve does.

Usage: python3 mhfe-fast-mode.py [OPTIONS] [FILE]

Arguments:
  [FILE]        The HTML file of the browser tool; mhfe-fast-mode.sha256 must
                lie next to it. Without it, the page that mhfe-fast-mode.sha256
                next to this script names.

Options:
  --no-browser  Print the address instead of opening the browser
  -h, --help    Print help

Examples:
  python3 mhfe-fast-mode.py
      Serve the page next to this script, as a double-click does

  python3 mhfe-fast-mode.py --no-browser tool.html
      Serve the page and print its address to open by hand

The page is served only when mhfe-fast-mode.sha256 lies next to it and holds its
SHA-256, and only to this computer (127.0.0.1). It sees none of your secrets:
all the work happens in the page.
"""


class Parser(argparse.ArgumentParser):
    """argparse, with its error messages shown as every other message is: a mistyped argument may
    hold control characters (AUD-018); and its help in mhfe's sections, without argparse's own
    colours (Python 3.14 adds them)."""

    def __init__(self, **options):
        try:
            super().__init__(color=False, **options)
        except TypeError:
            super().__init__(**options)

    def format_help(self):
        return HELP

    def error(self, message):
        error(shown(message))
        self.exit(INVALID_INPUT)


def shown(text):
    """`text` as a message shows it, every control character escaped as \\u{1b}, so that a terminal
    shows a folder or file name instead of carrying it out (AUD-015-SEC002): style::escaped in
    src/bin/mhfe/style.rs, which this script cannot import, and verify-fast-mode-script.py keeps
    the two alike."""
    return "".join(
        "\\u{{{:x}}}".format(ord(c)) if unicodedata.category(c) == "Cc" else c for c in str(text)
    )


def response(status, reason, body, content_type="text/plain; charset=utf-8", head_only=False):
    """One complete HTTP response. For HEAD the length of the body is sent without the body."""
    lines = [
        "HTTP/1.1 {} {}".format(status, reason),
        "Content-Type: {}".format(content_type),
        "Content-Length: {}".format(len(body)),
        "Connection: close",
    ]
    lines += ["{}: {}".format(name, value) for name, value in SECURITY_HEADERS]
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    return head if head_only else head + body


def error_response(status, reason):
    return response(status, reason, "{} {}\n".format(status, reason).encode("ascii"))


def respond(head, host, page):
    """The whole routing: GET or HEAD of "/" with the exact Host header gets the page, anything
    else an error. The Host check stops DNS rebinding: a web page on another site whose name was
    made to resolve to 127.0.0.1 would send its own name as Host."""
    lines = head.split("\n")
    request_line = lines[0].rstrip("\r")
    parts = request_line.split(" ")
    if len(parts) != 3 or "" in parts:
        return error_response(400, "Bad Request")
    method, target, version = parts
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        return error_response(400, "Bad Request")

    hosts = []
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if colon and name.strip().lower() == "host":
            hosts.append(value.strip())
    if hosts != [host]:
        return error_response(403, "Forbidden")

    if target != "/":
        return error_response(404, "Not Found")
    if method not in ("GET", "HEAD"):
        return error_response(405, "Method Not Allowed")
    return response(200, "OK", page, "text/html; charset=utf-8", head_only=method == "HEAD")


def read_request_head(connection, deadline):
    """The request head up to its empty line, as text. Raises ValueError for a head that is too
    long, ends early or is not ASCII, and socket.timeout once `deadline` has passed."""
    received = b""
    while True:
        end = received.find(b"\r\n\r\n")
        if end < 0:
            # A bare line feed also ends a line, as in the Rust version.
            end = received.find(b"\n\n")
        if end >= 0:
            return received[:end].decode("ascii")
        if len(received) >= MAX_REQUEST_HEAD:
            raise ValueError("request head too long")
        remaining = deadline - time.monotonic()
        # A zero or negative timeout would not wait at all or would mean "for ever".
        if remaining <= 0:
            raise socket.timeout("request deadline passed")
        connection.settimeout(remaining)
        chunk = connection.recv(MAX_REQUEST_HEAD - len(received))
        if not chunk:
            raise ValueError("the connection closed before the end of the request head")
        received += chunk


def answer(connection, host, page, deadline_seconds):
    """Reads one request and writes one response, then closes the connection."""
    try:
        try:
            head = read_request_head(connection, time.monotonic() + deadline_seconds)
            reply = respond(head, host, page)
        except (ValueError, UnicodeDecodeError):
            reply = error_response(400, "Bad Request")
        connection.settimeout(RESPONSE_DEADLINE)
        connection.sendall(reply)
    except OSError:
        pass  # A failed or slow connection is dropped; the server goes on serving the page.
    finally:
        connection.close()


def serve(listener, host, page, deadline_seconds=REQUEST_DEADLINE):
    """Answers every connection in its own thread, at most MAX_CONNECTIONS at a time."""
    slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
    listener.settimeout(ACCEPT_INTERVAL)

    def handle(connection):
        try:
            answer(connection, host, page, deadline_seconds)
        finally:
            slots.release()

    while True:
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue  # No connection yet; looking again lets Ctrl+C through.
        except OSError:
            if listener.fileno() == -1:
                return  # The listener was closed.
            # A connection that cannot be accepted is dropped, after a pause, and serving goes on,
            # as mhfe serve does (AUD-023-FUN003).
            time.sleep(ACCEPT_ERROR_PAUSE)
            continue
        if not slots.acquire(blocking=False):
            connection.close()
            continue
        try:
            threading.Thread(target=handle, args=(connection,), daemon=True).start()
        except RuntimeError:
            # The thread never ran, so its connection is closed here and its slot given back.
            connection.close()
            slots.release()


def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


def read_checksum_file(directory):
    """The SHA-256 and the page name from the checksum file in `directory`."""
    path = os.path.join(directory, CHECKSUM_FILE)
    try:
        with open(path, encoding="utf-8") as file:
            text = file.read()
    # A file that is not UTF-8 is refused as `mhfe serve` refuses it, not with a traceback.
    except (OSError, UnicodeDecodeError) as error:
        raise Refused(
            "There is no readable {} in {}: {}. The fast mode serves a page only when its checksum "
            "file lies next to it; nothing was served.".format(
                CHECKSUM_FILE, shown(directory), shown(getattr(error, "strerror", None) or error)
            )
        )
    malformed = Refused(
        "{} must hold exactly one line: the page's SHA-256, two spaces and its file name, or one "
        "space and * before the name; nothing was served.".format(shown(path))
    )
    # Lines as Rust's str::lines splits them: at "\n", without a "\r" before it.
    lines = [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]
    lines = [line for line in lines if line.strip(RUST_WHITESPACE)]
    if len(lines) != 1:
        raise malformed
    parts = split_checksum_line(lines[0])
    if parts is None:
        raise malformed
    digest, name = parts
    name = name.rstrip(RUST_WHITESPACE)
    # The name is a plain file name next to the checksum file, never a path, and holds no control
    # character, which a terminal would carry out where the name is shown (AUD-015-SEC002).
    plain_name = (
        "/" not in name
        and "\\" not in name
        and name not in (".", "..")
        and not any(unicodedata.category(c) == "Cc" for c in name)
    )
    hexadecimal = all(c in "0123456789abcdefABCDEF" for c in digest)
    if not (hexadecimal and name.endswith(".html") and plain_name):
        raise malformed
    return digest.lower(), name


def split_checksum_line(line):
    """The digest and the file name of a line in the format sha256sum writes: 64 digits, a space,
    then a second space in text mode (--text) or "*" in binary mode (--binary), then the name.
    None for any other line. Only that one marker is removed; a name that itself starts with "*"
    stays as it is and so does not match the page."""
    digest = line[:SHA256_HEX_DIGITS]
    separator = line[SHA256_HEX_DIGITS:SHA256_HEX_DIGITS + 2]
    if len(digest) != SHA256_HEX_DIGITS or separator not in ("  ", " *"):
        return None
    return digest, line[SHA256_HEX_DIGITS + 2:]


def load_checked_page(path):
    """The page, read once, after its checksum file next to it has named it with a matching
    SHA-256. Raises Refused otherwise."""
    directory = os.path.dirname(os.path.abspath(path))
    expected, listed_name = read_checksum_file(directory)
    if listed_name != os.path.basename(path):
        raise Refused(
            "{} names {}, not {}; nothing was served.".format(
                CHECKSUM_FILE, listed_name, shown(os.path.basename(path))
            )
        )
    try:
        with open(path, "rb") as file:
            page = file.read()
    except OSError as error:
        raise Refused(
            "Cannot read {}: {}; nothing was served.".format(shown(path), shown(error.strerror or error))
        )
    digest = sha256_of(page)
    if digest != expected:
        raise Refused(
            "The SHA-256 of {} is {}, but {} expects {}. The page has changed or is not the one "
            "released; nothing was served.".format(
                shown(os.path.basename(path)), digest, CHECKSUM_FILE, expected
            )
        )
    return page, digest


def main(arguments):
    parser = Parser(
        prog="mhfe-fast-mode.py",
        description="Serve an MHFE browser tool on this computer (127.0.0.1) in fast mode.",
    )
    parser.add_argument(
        "file", nargs="?", help="the HTML file; {} must lie next to it".format(CHECKSUM_FILE)
    )
    parser.add_argument(
        "--no-browser", action="store_true", help="print the address instead of opening the browser"
    )
    options = parser.parse_args(arguments)

    title()
    try:
        if options.file is None:
            here = os.path.dirname(os.path.abspath(__file__))
            if not os.path.isfile(os.path.join(here, CHECKSUM_FILE)):
                error(
                    "Put the tool's HTML file and its checksum file {} next to this script, or "
                    "run: python3 mhfe-fast-mode.py <file.html>".format(CHECKSUM_FILE)
                )
                return INVALID_INPUT
            path = os.path.join(here, read_checksum_file(here)[1])
        else:
            path = options.file
        page, digest = load_checked_page(path)
    except Refused as refusal:
        error(str(refusal))
        return INVALID_INPUT
    # The digest on a line of its own, so that wrapping never splits it, as mhfe serve shows it.
    ok("SHA-256 of {} verified".format(shown(os.path.basename(path))))
    fact("SHA-256", paint(MUTED, digest))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(MAX_CONNECTIONS)
    port = listener.getsockname()[1]
    address = "http://127.0.0.1:{}/".format(port)
    # The address holds no secret, so handing it to the browser is safe.
    # The address is always shown, as mhfe serve shows it: an opener that starts can still fail,
    # or open an unwanted browser (AUD-023-UI010).
    shown_address = paint(ACCENT, address)
    if options.no_browser or not webbrowser.open(address):
        say(["Open {} in your browser.".format(shown_address)])
    else:
        say(["Opened {}; if no browser shows it, open it yourself.".format(shown_address)])
    ok("{} {}".format(
        paint(GOOD, "Fast mode is running."),
        paint(MUTED, "Close this window or press Ctrl+C to stop."),
    ))
    try:
        serve(listener, "127.0.0.1:{}".format(port), page)
    except KeyboardInterrupt:
        say(["", "Stopped."])
        return SUCCESS
    finally:
        listener.close()
    # serve() returns only when its listener closes, which nothing but this function does: say so,
    # with a code that keeps a double-clicked window open (AUD-023-FUN003).
    error("The server stopped serving unexpectedly.")
    return INTERNAL_ERROR


def started_by_double_click(arguments):
    """Without arguments in a terminal window of its own, as a double-click starts it."""
    return not arguments and sys.stdin is not None and sys.stdin.isatty()


if __name__ == "__main__":
    # The marks ✓ and ✗ reach a console with a legacy code page as "?" rather than as an error.
    sys.stderr.reconfigure(errors="replace")
    code = main(sys.argv[1:])
    if code != SUCCESS and started_by_double_click(sys.argv[1:]):
        # Keep the window open so that the message can be read.
        input("Press Enter to close.")
    sys.exit(code)
