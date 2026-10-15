#!/usr/bin/env python3
# long: the distributed launcher must run as one file without modules.
"""Fast mode for an MHFE browser tool, for computers with Python but
without the mhfe program.

A browser runs the four Argon2 lanes of MHFE in parallel only on a
cross-origin isolated page, and a page opened as a file is never
isolated. This script serves one HTML file from 127.0.0.1 with the
headers that make it isolated, and opens it in the browser. It does what
`mhfe serve` does, with the same limits, and never receives or processes
a secret: the page does all the work.

It serves a page only when the checksum file mhfe-fast-mode.sha256 lies
next to it and names it with a matching SHA-256; otherwise it refuses
with a message and serves nothing. The page's name must end in
lower-case .html; .htm and .HTML are not accepted.

Usage:
python3 mhfe-fast-mode.py              serve the page named in the
mhfe-fast-mode.sha256 next
to this script, as a double-click does
python3 mhfe-fast-mode.py tool.html    serve tool.html;
mhfe-fast-mode.sha256 must lie next
to it and name it
--no-browser                           print the address instead of
opening the browser

Needs Python 3.8 or later and nothing else. It answers GET and HEAD of
"/" only, checks the Host header against DNS rebinding, ignores request
bodies and logs nothing.
"""

import argparse
import hashlib
import os
import re
import signal
import socket
import stat
import sys
import threading
import time
import unicodedata
import webbrowser

# The same limits as `mhfe serve` (src/bin/mhfe/serve.rs).
# Longest request head accepted; real browsers send far less.
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
MAX_REQUEST_HEAD = 16 * 1024
# Seconds a client has for its whole request head. A limit on each read
# alone would let a client
# that sends one byte at a time keep its connection open for ever.
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
REQUEST_DEADLINE = 10.0
# Seconds for sending the whole answer. Since Python 3.5 a socket
# timeout limits the total time
# of sendall, not each piece it sends, so a client that reads slowly
# cannot stretch it.
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
RESPONSE_DEADLINE = 10.0
# Connections answered at the same time; any further one is closed at
# once. A browser opens only
# a few, and the cap keeps a flood of connections from starting a thread
# each.
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
MAX_CONNECTIONS = 16
# Seconds the listener waits after a connection it could not accept,
# such as when the process has
# no file descriptor left, so that it does not spin; it then goes on
# serving (AUD-023-FUN003).
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
ACCEPT_ERROR_PAUSE = 0.1
# Seconds the listener waits for a connection before it looks again. On
# Windows a waiting
# accept() does not notice Ctrl+C, so the wait is kept short.
ACCEPT_INTERVAL = 1.0

# Sent with every response. COOP and COEP make the page cross-origin
# isolated; the others keep it
# from being framed, sniffed, cached or followed by a referrer.
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
SECURITY_HEADERS = (
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Embedder-Policy", "require-corp"),
    ("Content-Security-Policy", "frame-ancestors 'none'"),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
)

# The checksum file that must lie next to the page, as for `mhfe serve`.
# Its name never changes,
# so a tool can ship it beside its HTML file. It holds one line in the
# format sha256sum writes:
# the SHA-256 of the page, a space, a mode marker (a second space in
# text mode, "*" in binary
# mode) and the page's file name.
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
CHECKSUM_FILE = "mhfe-fast-mode.sha256"
# Deliberate copy from serve.rs; launcher tests compare the suffix and
# refusal template.
HTML_SUFFIX = ".html"
NON_HTML = (
    "The fast mode serves only a page whose name ends in lower-case {suffix}; "
    "nothing was served."
)
# Hexadecimal digits of a SHA-256 digest.
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
SHA256_HEX_DIGITS = 64
# The most a checksum file may hold; its one line is about 80 bytes. A
# longer file is malformed,
# and nothing beyond this is read of it (AUD-024-FUN005).
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
MAX_CHECKSUM_FILE = 4 * 1024
# The most a page may hold; a tool's page is a few megabytes. A larger
# file is refused, and nothing
# beyond this is read of it (AUD-024-FUN005).
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
MAX_PAGE = 64 * 1024 * 1024

# Exit codes, as the mhfe program uses them.
# Deliberate copy: exit.rs; this launcher ships without Rust.
SUCCESS = 0
# Deliberate copy: exit.rs; this launcher ships without Rust.
INTERNAL_ERROR = 1
# Deliberate copy: exit.rs; this launcher ships without Rust.
INVALID_INPUT = 2
# Deliberate copy from exit.rs and terminal.rs: the standalone launcher
# cannot import Rust.
# The launcher tests compare both the cancellation code and sentence
# with those sources.
CANCELLED = 130
CANCELLED_TEXT = "Cancelled. Nothing was saved."

# The terminal style of mhfe (src/bin/mhfe/style.rs), with the standard
# library alone
# (AUD-023-UI011): a title line, a tick before what went right, "✗
# Error:" before a refusal, lines
# of at most 78 columns, and colours only for a terminal that shows
# them.
# Deliberate copy of the constants of style.rs: this launcher ships
# beside the browser package for
# computers without the mhfe program, so it cannot import the Rust code.
# test_the_style_constants_match_the_rust_launcher in
# scripts/verify-fast-mode-script.py reads
# them from style.rs and keeps both in step.
TEXT_WIDTH = 78
HELP_WIDTH = 80
FACT_LABEL_WIDTH = 10
TICK = "✓"
ERROR_MARK = "✗ Error:"
# The SGR codes of the styles in style.rs, compared by the launcher
# test.
HEADING, ACCENT, STRONG, MUTED, GOOD, BAD = "1;36", "36", "1", "90", "1;32", "1;31"
WARNING = "1;33"
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
TITLE = "Fast mode"
# A colour code as paint() writes it, which takes no column.
COLOUR_CODE = re.compile("\x1b\\[[0-9;]*m")


class Refused(Exception):
    """The file cannot be served; the message says why."""


# The characters Rust's str::trim takes off (Unicode White_Space), so
# that a checksum line reads
# here as `mhfe serve` reads it (src/bin/mhfe/serve.rs); Python's own
# strip() also takes U+001C to
# U+001F, which are control characters there.
RUST_WHITESPACE = (
    "\t\n\x0b\x0c\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009"
    "\u200a\u2028\u2029\u202f\u205f\u3000"
)


def colours(stream):
    """Whether `stream` shows colours: anstream with the CORE-38
    dumb-terminal override. NO_COLOR, when not empty, turns them off;
    then CLICOLOR_FORCE, when not empty, even "0", turns them on; then
    CLICOLOR=0 turns them off; otherwise only a terminal shows them, and
    only with TERM set and not "dumb", with CLICOLOR set or with CI set.
    TERM=dumb forbids that automatic colour. Deliberate copy, as this
    script cannot call Rust; test_colours_follow_the_workspace_rule
    checks the answers. Never on Windows, whose console this script
    cannot switch to colours.
    """
    environment = os.environ
    if os.name == "nt":
        return False
    if environment.get("NO_COLOR", ""):
        return False
    if environment.get("CLICOLOR_FORCE", ""):
        return True
    clicolor = environment.get("CLICOLOR")
    if clicolor == "0":
        return False
    term = environment.get("TERM")
    if term == "dumb":
        return False
    capable = term is not None and term != "dumb"
    return stream.isatty() and (capable or clicolor is not None or "CI" in environment)


def coloured(style, text):
    """`text` in `style`, an SGR code."""
    return "\x1b[{}m{}\x1b[0m".format(style, text)


def paint(style, text, stream=None):
    """
    `text` in `style` where `stream`, standard error unless given, shows
    colours.
    """
    return coloured(style, text) if colours(sys.stderr if stream is None else stream) else text


# Deliberate copy: style::visible_width (ASCII and ANSI text); launcher
# ships without Rust.
# Launcher parity tests cover shared messages and display cases.
def visible_width(text):
    """The columns of `text` without its colour codes, as
    style::visible_width counts them, but in characters: a wide
    character, which only a file name may hold here, counts as one.
    """
    return len(COLOUR_CODE.sub("", text))


# Deliberate copy: style::wrap; launcher ships without Rust.
# Launcher parity tests cover shared messages and display cases.
def wrapped(text, width):
    """
    `text` in lines of at most `width` visible columns, broken at spaces
    and never inside a word, a line break kept: style::wrap. Colour
    codes take no column, so a coloured text breaks where its plain text
    does.
    """
    if not text:
        return [""]
    lines = []
    for paragraph in text.split("\n"):
        line, line_width = "", 0
        for word in (word for word in paragraph.split(" ") if word):
            word_width = visible_width(word)
            if line_width > 0 and line_width + 1 + word_width > width:
                lines.append(line)
                line, line_width = "", 0
            if line_width > 0:
                line += " "
                line_width += 1
            line += word
            line_width += word_width
        lines.append(line)
    return lines


def say(lines):
    for line in lines:
        print(line, file=sys.stderr)


def title():
    """The first line, as every mhfe command starts: "MHFE · Fast mode"
    after a blank line.
    """
    say(["", "{} {} {}".format(paint(HEADING, "MHFE"), paint(MUTED, "·"), paint(STRONG, TITLE))])


def ok(text):
    """Something that went right: a tick, the text wrapped and indented
    under it.
    """
    lines = wrapped(text, TEXT_WIDTH - 2)
    say(["{} {}".format(paint(GOOD, TICK), lines[0])] + ["  " + line for line in lines[1:]])


def fact(label, value):
    """A labelled value on a line of its own, as style::fact shows it.
    """
    say(["  {} {}".format(paint(MUTED, label.ljust(FACT_LABEL_WIDTH)), value)])


def error(text):
    """
    A refusal: "✗ Error:", then the text wrapped under it, as mhfe shows
    an error.
    """
    indent = len(ERROR_MARK) + 1
    lines = wrapped(text, TEXT_WIDTH - indent)
    first = "{} {}".format(paint(BAD, ERROR_MARK), lines[0])
    say(["", first] + [" " * indent + line for line in lines[1:]])


# The closing grey note of `mhfe serve --help`; the safety line follows
# it.
# Deliberate copy: serve.rs; this launcher ships without Rust.
# verify-fast-mode-script.py compares the standalone copies.
HELP_NOTE = (
    "The page is served only when {} lies next to it and holds its SHA-256, and only to this "
    "computer (127.0.0.1). It sees none of your secrets: all the work happens in the page."
).format(CHECKSUM_FILE)
# Deliberate copy of style::SAFETY_LINE; the launcher parity test
# compares the exact text.
SAFETY_LINE = "Experimental: not independently reviewed; do not use it to protect real funds."


def help_text(colour):
    """
    The help, in the sections, words and colours of `mhfe serve --help`
    (style::help_styles and style::help_note): headings in bold cyan,
    the command, options and examples in cyan, placeholders and the
    closing note in grey; plain text when `colour` is false.
    """

    def look(style, text):
        return coloured(style, text) if colour else text

    command = "python3 mhfe-fast-mode.py"
    note = "".join(look(MUTED, line) + "\n" for line in wrapped(HELP_NOTE, HELP_WIDTH))
    note += "\n" + look(WARNING, SAFETY_LINE) + "\n"
    return """Serve an MHFE browser tool on this computer in fast mode

A browser runs the faster, multi-threaded Argon2 only on a page served with
special headers. This script serves one page from this computer (127.0.0.1)
with those headers and opens it in the browser, as mhfe serve does.

{usage} {command} {options} {file}

{arguments}
  {file}        The HTML file of the browser tool; mhfe-fast-mode.sha256 must
                lie next to it. Name must end in lower-case {suffix}.
                Without it, the page that mhfe-fast-mode.sha256
                next to this script names.

{options_heading}
  {no_browser}  Print the address instead of opening the browser
  {short_help}, {long_help}    Print help

{examples}
  {command}
      Serve the page next to this script, as a double-click does

  {example}
      Serve the page and print its address to open by hand

{note}""".format(
        usage=look(HEADING, "Usage:"),
        command=look(ACCENT, command),
        options=look(MUTED, "[OPTIONS]"),
        file=look(MUTED, "[FILE]"),
        arguments=look(HEADING, "Arguments:"),
        suffix=HTML_SUFFIX,
        options_heading=look(HEADING, "Options:"),
        no_browser=look(ACCENT, "--no-browser"),
        short_help=look(ACCENT, "-h"),
        long_help=look(ACCENT, "--help"),
        examples=look(HEADING, "Examples:"),
        example=look(ACCENT, command + " --no-browser tool.html"),
        note=note,
    )


# The help without colours, as a pipe or a file gets it.
HELP = help_text(False)


class Parser(argparse.ArgumentParser):
    """
    argparse, with its error messages shown as every other message is: a
    mistyped argument may hold control characters (AUD-018); and its
    help in mhfe's sections and colours, without argparse's own colours
    (Python 3.14 adds them).
    """

    def __init__(self, **options):
        try:
            super().__init__(color=False, **options)
        except TypeError:
            super().__init__(**options)

    def format_help(self):
        # argparse prints the help to standard output, so that stream
        # decides the colours.
        return help_text(colours(sys.stdout))

    def error(self, message):
        error(shown(message))
        self.exit(INVALID_INPUT)


# Deliberate copy: style::escaped; launcher ships without Rust.
# Launcher parity tests cover shared messages and display cases.
def shown(text):
    """`text` as a message shows it, every control character escaped as
    \\u{1b}, so that a terminal shows a folder or file name instead of
    carrying it out (AUD-015-SEC002): style::escaped in
    src/bin/mhfe/style.rs, which this script cannot import, and
    verify-fast-mode-script.py keeps the two alike.
    """
    return "".join(
        "\\u{{{:x}}}".format(ord(c)) if unicodedata.category(c) == "Cc" else c for c in str(text)
    )


def response(status, reason, body, content_type="text/plain; charset=utf-8", head_only=False):
    """
    One complete HTTP response. For HEAD the length of the body is sent
    without the body.
    """
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


def rust_lines(text):
    """
    The lines of `text` as Rust's str::lines gives them: each ends at a
    "\n", which goes with one "\r" before it; a last line without "\n"
    keeps any "\r".
    """
    pieces = text.split("\n")
    lines = [piece[:-1] if piece.endswith("\r") else piece for piece in pieces[:-1]]
    return lines + [pieces[-1]] if pieces[-1] else lines


def respond(head, host, page):
    """The whole routing: GET or HEAD of "/" with the exact Host header
    gets the page, anything else an error. The Host check stops DNS
    rebinding: a web page on another site whose name was made to resolve
    to 127.0.0.1 would send its own name as Host. A deliberate copy of
    respond in src/bin/mhfe/serve.rs, read line by line as it reads
    them; both are held to the request heads of
    tests/fixtures/fast-mode-cases.json (AUD-024-FUN007).
    """
    lines = rust_lines(head)
    request_line = lines[0] if lines else ""
    parts = request_line.split(" ")
    if len(parts) != 3:
        return error_response(400, "Bad Request")
    method, target, version = parts
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        return error_response(400, "Bad Request")

    hosts = []
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        # As Rust's trim and eq_ignore_ascii_case: only ASCII letters
        # change case.
        name = name.strip(RUST_WHITESPACE)
        if colon and name.isascii() and name.lower() == "host":
            hosts.append(value.strip(RUST_WHITESPACE))
    if hosts != [host]:
        return error_response(403, "Forbidden")

    if target != "/":
        return error_response(404, "Not Found")
    if method not in ("GET", "HEAD"):
        return error_response(405, "Method Not Allowed")
    return response(200, "OK", page, "text/html; charset=utf-8", head_only=method == "HEAD")


def head_end(received):
    """
    Where the request head in `received` ends, after its empty line, or
    -1 before that: lines end at "\n", and an empty one is "\n" or
    "\r\n", as read_request_head in src/bin/mhfe/serve.rs reads them one
    by one.
    """
    start = 0
    while True:
        end = received.find(b"\n", start)
        if end < 0:
            return -1
        if received[start:end] in (b"", b"\r"):
            return end + 1
        start = end + 1


def read_request_head(connection, deadline):
    """The request head up to and with its empty line, as text. Raises
    ValueError for a head that is too long, ends early or is not UTF-8,
    and socket.timeout once `deadline` has passed.
    """
    received = b""
    while True:
        end = head_end(received)
        if end >= 0:
            return received[:end].decode("utf-8")
        if len(received) >= MAX_REQUEST_HEAD:
            raise ValueError("request head too long")
        remaining = deadline - time.monotonic()
        # A zero or negative timeout would not wait at all or would mean
        # "for ever".
        if remaining <= 0:
            raise socket.timeout("request deadline passed")
        connection.settimeout(remaining)
        chunk = connection.recv(MAX_REQUEST_HEAD - len(received))
        if not chunk:
            raise ValueError("the connection closed before the end of the request head")
        received += chunk


def answer(connection, host, page, deadline_seconds):
    """Reads one request and writes one response, then closes the
    connection.
    """
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
    """
    Answers every connection in its own thread, at most MAX_CONNECTIONS
    at a time.
    """
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
            # A connection that cannot be accepted is dropped, after a
            # pause, and serving goes on,
            # as mhfe serve does (AUD-023-FUN003).
            time.sleep(ACCEPT_ERROR_PAUSE)
            continue
        if not slots.acquire(blocking=False):
            connection.close()
            continue
        try:
            threading.Thread(target=handle, args=(connection,), daemon=True).start()
        except RuntimeError:
            # The thread never ran, so its connection is closed here and
            # its slot given back.
            connection.close()
            slots.release()


def sha256_of(data):
    return hashlib.sha256(data).hexdigest()


def read_regular_file(path, limit):
    """At most `limit` bytes of `path`, which must be a regular file: a
    FIFO, a device or a folder is refused before anything is read,
    opened without waiting so that a FIFO with no writer does not block.
    None for a longer file, of which nothing beyond the limit is read.
    As read_regular_file in src/bin/mhfe/serve.rs (AUD-024-FUN005).
    """
    # Windows refuses to open a directory before fstat can check it.
    require_regular_file(os.stat(path))
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    try:
        # The path may have been replaced since stat checked it.
        require_regular_file(os.fstat(descriptor))
        file = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    with file:
        data = file.read(limit + 1)
    return data if len(data) <= limit else None


def require_regular_file(metadata):
    if not stat.S_ISREG(metadata.st_mode):
        raise OSError("it is not a regular file")


# Deliberate copy: serve::read_checksum_file; launcher ships without
# Rust.
# Launcher parity tests cover shared messages and display cases.
def read_checksum_file(directory):
    """
    The SHA-256 and the page name from the checksum file in `directory`.
    """
    path = os.path.join(directory, CHECKSUM_FILE)
    try:
        data = read_regular_file(path, MAX_CHECKSUM_FILE)
        # Decoded whole, so that a lone "\r" ends no line, as in mhfe
        # serve (AUD-024-FUN006).
        text = None if data is None else data.decode("utf-8")
    # A file that is not UTF-8 is refused as `mhfe serve` refuses it,
    # not with a traceback.
    except (OSError, UnicodeDecodeError) as error:
        raise Refused(
            "There is no readable {} in {}: {}. "
            "The fast mode serves a page only when its checksum "
            "file lies next to it; nothing was served.".format(
                CHECKSUM_FILE, shown(directory), shown(getattr(error, "strerror", None) or error)
            )
        )
    # Deliberate copy of MALFORMED in src/bin/mhfe/serve.rs, as this
    # script cannot import the Rust
    # code; test_the_checksum_format_is_said_as_mhfe_serve_says_it in
    # scripts/verify-fast-mode-script.py keeps the two alike.
    malformed = Refused(
        "{} must hold exactly one line: the page's SHA-256, two spaces and its file name, or one "
        "space and * before the name; nothing was served.".format(shown(path))
    )
    if text is None:
        raise malformed
    lines = [line for line in rust_lines(text) if line.strip(RUST_WHITESPACE)]
    if len(lines) != 1:
        raise malformed
    parts = split_checksum_line(lines[0])
    if parts is None:
        raise malformed
    digest, name = parts
    name = name.rstrip(RUST_WHITESPACE)
    # The name is a plain file name next to the checksum file, never a
    # path, and holds no control
    # character, which a terminal would carry out where the name is
    # shown (AUD-015-SEC002).
    plain_name = (
        "/" not in name
        and "\\" not in name
        and name not in (".", "..")
        and not any(unicodedata.category(c) == "Cc" for c in name)
    )
    hexadecimal = all(c in "0123456789abcdefABCDEF" for c in digest)
    if not (hexadecimal and plain_name):
        raise malformed
    if not name.endswith(HTML_SUFFIX):
        raise Refused(NON_HTML.format(suffix=HTML_SUFFIX))
    return digest.lower(), name


def split_checksum_line(line):
    """The digest and the file name of a line in the format sha256sum
    writes: 64 digits, a space, then a second space in text mode
    (--text) or "*" in binary mode (--binary), then the name. None for
    any other line. Only that one marker is removed; a name that itself
    starts with "*" stays as it is and so does not match the page.
    """
    digest = line[:SHA256_HEX_DIGITS]
    separator = line[SHA256_HEX_DIGITS:SHA256_HEX_DIGITS + 2]
    if len(digest) != SHA256_HEX_DIGITS or separator not in ("  ", " *"):
        return None
    return digest, line[SHA256_HEX_DIGITS + 2:]


# Deliberate copy: serve::load_checked_page; launcher ships without
# Rust.
# Launcher parity tests cover shared messages and display cases.
def load_checked_page(path):
    """
    The page, read once, after its checksum file next to it has named it
    with a matching SHA-256. Raises Refused otherwise.
    """
    directory = os.path.dirname(os.path.abspath(path))
    expected, listed_name = read_checksum_file(directory)
    if listed_name != os.path.basename(path):
        raise Refused(
            "{} names {}, not {}; nothing was served.".format(
                CHECKSUM_FILE, listed_name, shown(os.path.basename(path))
            )
        )
    try:
        page = read_regular_file(path, MAX_PAGE)
    except OSError as error:
        raise Refused(
            "Cannot read {}: {}; nothing was served.".format(shown(path),
                shown(error.strerror or error))
        )
    if page is None:
        raise Refused(
            ("{} is larger than {} MiB, more than any page of the tools; "
             "nothing was served.").format(
                shown(path), MAX_PAGE >> 20
            )
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


# Deliberate copy: serve::run; launcher ships without Rust.
# Launcher parity tests cover shared messages and display cases.
def main(arguments):
    parser = Parser(
        prog="mhfe-fast-mode.py",
        description="Serve an MHFE browser tool on this computer (127.0.0.1) in fast mode.",
    )
    parser.add_argument(
        "file", nargs="?", help="the HTML file; {} must lie next to it".format(CHECKSUM_FILE)
    )
    parser.add_argument(
        "--no-browser", action="store_true",
            help="print the address instead of opening the browser"
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
    # The digest on a line of its own, so that wrapping never splits it,
    # as mhfe serve shows it.
    ok("SHA-256 of {} verified".format(shown(os.path.basename(path))))
    fact("SHA-256", paint(MUTED, digest))

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(MAX_CONNECTIONS)
    port = listener.getsockname()[1]
    address = "http://127.0.0.1:{}/".format(port)
    # The address holds no secret, so handing it to the browser is safe.
    # The address is always shown, as mhfe serve shows it: an opener
    # that starts can still fail,
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
        return cancelled()
    finally:
        listener.close()
    # serve() returns only when its listener closes, which nothing but
    # this function does: say so,
    # with a code that keeps a double-clicked window open
    # (AUD-023-FUN003).
    error("The server stopped serving unexpectedly.")
    return INTERNAL_ERROR


def cancelled():
    """Reports the same requested stop as the native launcher."""
    say(["", "{} {}".format(paint(WARNING, "!"), CANCELLED_TEXT)])
    return CANCELLED


def stop_requested(_number, _frame):
    """
    Lets the main thread close its listener and report a requested stop.
    """
    raise KeyboardInterrupt


def run(arguments):
    """main(arguments), with an error it did not foresee, such as
    MemoryError, said as every other error, so that a double-clicked
    window stays open to show it (AUD-024-FUN005).
    """
    stops = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        stops.append(signal.SIGHUP)
    previous = {stop: signal.signal(stop, stop_requested) for stop in stops}
    try:
        return main(arguments)
    except KeyboardInterrupt:
        return cancelled()
    except Exception as unexpected:
        error("The fast mode stopped: {}.".format(shown(repr(unexpected))))
        return INTERNAL_ERROR
    finally:
        for stop, handler in previous.items():
            signal.signal(stop, handler)


def started_by_double_click(arguments):
    """
    Without arguments in a terminal window of its own, as a double-click
    starts it.
    """
    return not arguments and sys.stdin is not None and sys.stdin.isatty()


if __name__ == "__main__":
    # The marks ✓ and ✗ reach a console with a legacy code page as "?"
    # rather than as an error.
    sys.stderr.reconfigure(errors="replace")
    code = run(sys.argv[1:])
    if code not in (SUCCESS, CANCELLED) and started_by_double_click(sys.argv[1:]):
        # Keep the window open so that the message can be read.
        input("Press Enter to close.")
    sys.exit(code)
