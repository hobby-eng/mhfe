# TOOL-01: in-process tests of the standalone Python launcher and its
# sockets.
"""Tests of packaging/mhfe-fast-mode.py, the Python version of `mhfe
serve`.

They check the same cases as the tests in src/bin/mhfe/serve.rs, so that
both launchers behave alike, compare the limits, messages and style
constants the launcher copies with the Rust sources, and run a real
server on a free port of 127.0.0.1. Only the standard library is used.

Usage: python3 scripts/verify-fast-mode-script.py
"""

import ast
import contextlib
import io
import json
import os
import re
import socket
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

from fast_mode_fixture import (
    ANSI_COLOURS,
    COLOUR_CODE,
    COLOUR_VARIABLES,
    HOST,
    PAGE,
    ROOT,
    SCRIPT,
    SHARED_CASES,
    Screen,
    fast_mode,
    filled,
    message_shape,
    request,
    rust_constant,
    rust_source,
    rust_string,
    sgr,
    status_line,
)


class Routing(unittest.TestCase):
    def test_serves_the_page_with_every_security_header(self):
        reply = fast_mode.respond(request("GET", "/", HOST), HOST, PAGE)
        self.assertEqual(status_line(reply), "HTTP/1.1 200 OK")
        text = reply.decode("ascii")
        self.assertIn("Content-Type: text/html; charset=utf-8\r\n", text)
        for name, value in fast_mode.SECURITY_HEADERS:
            self.assertIn("{}: {}\r\n".format(name, value), text)
        self.assertTrue(reply.endswith(PAGE))

    def test_head_sends_the_headers_without_the_body(self):
        reply = fast_mode.respond(request("HEAD", "/", HOST), HOST, PAGE)
        self.assertEqual(status_line(reply), "HTTP/1.1 200 OK")
        self.assertIn("Content-Length: {}\r\n".format(len(PAGE)), reply.decode("ascii"))
        self.assertTrue(reply.endswith(b"\r\n\r\n"))

    def test_the_security_headers_match_the_rust_launcher(self):
        rust = rust_source("serve.rs")
        for name, value in fast_mode.SECURITY_HEADERS:
            self.assertIn('("{}", "{}")'.format(name, value), rust)
        count = len(fast_mode.SECURITY_HEADERS)
        self.assertIn("SECURITY_HEADERS: [(&str, &str); {}]".format(count), rust)

    def test_the_limits_match_the_rust_launcher(self):
        # The limits of serve.rs, read from its source, so that a change
        # to either launcher alone
        # fails here (AUD-023-ARC017).
        text = rust_source("serve.rs")

        def constant(name):
            return rust_constant(text, name)

        def seconds(value):
            match = re.fullmatch(r"Duration::from_(secs|millis)\((\d+)\)", value)
            return int(match.group(2)) / (1 if match.group(1) == "secs" else 1000)

        self.assertEqual(eval(constant("MAX_REQUEST_HEAD"), {}), fast_mode.MAX_REQUEST_HEAD)
        self.assertEqual(seconds(constant("REQUEST_DEADLINE")), fast_mode.REQUEST_DEADLINE)
        self.assertEqual(seconds(constant("RESPONSE_DEADLINE")), fast_mode.RESPONSE_DEADLINE)
        self.assertEqual(int(constant("MAX_CONNECTIONS")), fast_mode.MAX_CONNECTIONS)
        self.assertEqual(seconds(constant("ACCEPT_ERROR_PAUSE")), fast_mode.ACCEPT_ERROR_PAUSE)
        self.assertEqual(eval(constant("MAX_CHECKSUM_FILE"), {}), fast_mode.MAX_CHECKSUM_FILE)
        self.assertEqual(eval(constant("MAX_PAGE"), {}), fast_mode.MAX_PAGE)

    def test_every_shared_request_head_gets_its_status(self):
        # As in serve.rs, through the reading of the head and the
        # routing (AUD-024-FUN007).
        for case in SHARED_CASES["requestHeads"]:
            head = filled(case["head"], "")
            received = head.encode(case.get("encoding", "utf-8"))
            end = fast_mode.head_end(received)
            try:
                if end < 0:
                    raise ValueError("the connection closed before the end of the request head")
                reply = fast_mode.respond(received[:end].decode("utf-8"), HOST, PAGE)
            except (ValueError, UnicodeDecodeError):
                reply = fast_mode.error_response(400, "Bad Request")
            self.assertEqual(int(status_line(reply).split(" ")[1]), case["status"], repr(head))

    def test_refuses_other_hosts_against_dns_rebinding(self):
        for host in ["localhost:43210", "127.0.0.1", "127.0.0.1:1", "evil.example:43210", ""]:
            reply = fast_mode.respond(request("GET", "/", host), HOST, PAGE)
            self.assertEqual(status_line(reply), "HTTP/1.1 403 Forbidden", host)
        self.assertEqual(status_line(fast_mode.respond("GET / HTTP/1.1", HOST, PAGE)),
                         "HTTP/1.1 403 Forbidden")
        two_hosts = "GET / HTTP/1.1\r\nHost: {0}\r\nHost: {0}".format(HOST)
        self.assertEqual(status_line(fast_mode.respond(two_hosts, HOST, PAGE)),
                         "HTTP/1.1 403 Forbidden")

    def test_refuses_other_paths_and_methods(self):
        for target in ["/index.html", "/../", "//", "/?x=1", "*"]:
            reply = fast_mode.respond(request("GET", target, HOST), HOST, PAGE)
            self.assertEqual(status_line(reply), "HTTP/1.1 404 Not Found", target)
        for method in ["POST", "PUT", "DELETE", "OPTIONS", "get"]:
            reply = fast_mode.respond(request(method, "/", HOST), HOST, PAGE)
            self.assertEqual(status_line(reply), "HTTP/1.1 405 Method Not Allowed", method)
        for malformed in ["GET /", "GET / HTTP/2\r\nHost: x", "GET  / HTTP/1.1"]:
            reply = fast_mode.respond(malformed, HOST, PAGE)
            self.assertEqual(status_line(reply), "HTTP/1.1 400 Bad Request", malformed)


class Server(unittest.TestCase):
    """A real server on a free port, with a short request deadline."""

    def setUp(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(fast_mode.MAX_CONNECTIONS)
        self.port = self.listener.getsockname()[1]
        host = "127.0.0.1:{}".format(self.port)
        threading.Thread(target=fast_mode.serve, args=(self.listener, host, PAGE, 0.5),
                         daemon=True).start()

    def tearDown(self):
        self.listener.close()

    def connect(self):
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        self.addCleanup(connection.close)
        return connection

    def get(self):
        connection = self.connect()
        head = request("GET", "/", "127.0.0.1:{}".format(self.port)) + "\r\n"
        connection.sendall(head.encode("ascii"))
        reply = b""
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                return reply
            reply += chunk

    def test_serves_the_page(self):
        reply = self.get()
        self.assertEqual(status_line(reply), "HTTP/1.1 200 OK")
        self.assertTrue(reply.endswith(PAGE))

    def test_a_slow_client_neither_holds_up_others_nor_outlives_the_deadline(self):
        slow = self.connect()

        def drip():
            # One byte of a request head every 100 ms, never finished.
            for byte in b"GET / HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaa":
                try:
                    slow.sendall(bytes([byte]))
                except OSError:
                    return
                time.sleep(0.1)

        threading.Thread(target=drip, daemon=True).start()
        started = time.monotonic()
        self.assertEqual(status_line(self.get()), "HTTP/1.1 200 OK")
        self.assertLess(time.monotonic() - started, 0.4, "the page came at once")
        try:
            while slow.recv(4096):
                pass
        except OSError:
            pass
        self.assertLess(time.monotonic() - started, 2.0, "dropped at its deadline")

    def test_an_endless_request_head_is_refused(self):
        connection = self.connect()
        filler = b"GET / HTTP/1.1\r\n" + b"X-Filler: a\r\n" * 5000
        try:
            connection.sendall(filler)
        except OSError:
            pass  # The server may close before everything is sent.
        reply = b""
        try:
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                reply += chunk
        except OSError:
            pass
        self.assertEqual(status_line(reply), "HTTP/1.1 400 Bad Request")

    def test_a_client_that_does_not_read_is_dropped_at_the_response_deadline(self):
        # The counterpart of serve.rs's test: a large page to a client
        # that never reads
        # (AUD-023-ARC017).
        server, client = socket.socketpair()
        self.addCleanup(client.close)
        client.sendall((request("GET", "/", HOST) + "\r\n").encode("ascii"))
        original = fast_mode.RESPONSE_DEADLINE
        fast_mode.RESPONSE_DEADLINE = 0.5
        failures = []
        def send_response():
            try:
                fast_mode.answer(server, HOST, b"x" * (64 * 1024 * 1024), 5.0)
            except BaseException as error:
                failures.append(error)
        writer = threading.Thread(target=send_response, daemon=True)
        try:
            started = time.monotonic()
            writer.start()
            writer.join(timeout=3.0)
            self.assertFalse(writer.is_alive(),
                "response write did not finish within the test limit")
            if failures:
                raise failures[0]
            self.assertLess(time.monotonic() - started, 3.0, "dropped at the response deadline")
        finally:
            client.close()
            writer.join(timeout=1.0)
            fast_mode.RESPONSE_DEADLINE = original

    def test_connections_beyond_the_limit_are_closed_at_once(self):
        # Every slot is taken by a client that sends nothing until its
        # deadline.
        idle = [self.connect() for _ in range(fast_mode.MAX_CONNECTIONS)]
        time.sleep(0.1)
        extra = self.connect()
        extra.settimeout(2)
        started = time.monotonic()
        try:
            data = extra.recv(1)
        except OSError:
            data = b""
        self.assertEqual(data, b"", "the extra connection was closed without an answer")
        self.assertLess(time.monotonic() - started, 0.4, "closed at once, not at a deadline")
        self.assertEqual(len(idle), fast_mode.MAX_CONNECTIONS)


class Style(unittest.TestCase):
    def test_requested_stops_use_the_native_sentence_and_exit_code(self):
        self.assertEqual(fast_mode.CANCELLED, int(rust_constant(rust_source("exit.rs"),
            "CANCELLED")))
        self.assertIn('style::warn("{}", "")'.format(fast_mode.CANCELLED_TEXT),
                      rust_source("terminal.rs"))
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(fast_mode.cancelled(), fast_mode.CANCELLED)
        self.assertEqual(output.getvalue().strip(), "! " + fast_mode.CANCELLED_TEXT)

    """The launcher writes as mhfe serve does: its help in the same sections, colours and safety
    line, a title, marked success and error lines within 78 columns, and colours by the same
    environment rules (AUD-023-UI011)."""

    # anstream 1.0.0's answers (auto.rs, with anstyle-query 1.1.5),
    # which mhfe writes through, as
    # (environment, a terminal, colours): NO_COLOR first, then
    # CLICOLOR_FORCE with any value but
    # an empty one, then CLICOLOR=0, then a terminal with TERM set and
    # not dumb, CLICOLOR or CI.
    COLOUR_RULE_ANSWERS = (
        ({"TERM": "xterm-256color"}, True, True),
        ({"TERM": "xterm-256color"}, False, False),
        ({}, True, False),
        ({"TERM": "dumb"}, True, False),
        ({"TERM": "dumb", "CLICOLOR": "1"}, True, False),
        ({"TERM": "dumb", "CI": "true"}, True, False),
        ({"TERM": "dumb", "CI": "false"}, True, False),
        ({"TERM": "dumb", "CI": ""}, True, False),
        ({"CLICOLOR": "1"}, True, True),
        ({"CLICOLOR": "1"}, False, False),
        ({"CI": "true"}, True, True),
        ({"CI": "true"}, False, False),
        ({"TERM": "xterm", "CLICOLOR": "0"}, True, False),
        ({"TERM": "xterm", "NO_COLOR": "1"}, True, False),
        ({"TERM": "xterm", "NO_COLOR": ""}, True, True),
        ({"CLICOLOR_FORCE": "1"}, False, True),
        ({"CLICOLOR_FORCE": "0"}, False, True),
        ({"CLICOLOR_FORCE": ""}, False, False),
        ({"CLICOLOR_FORCE": "1", "NO_COLOR": "1"}, True, False),
        ({"CLICOLOR_FORCE": "1", "CLICOLOR": "0"}, False, True),
        ({"CLICOLOR_FORCE": "1", "TERM": "dumb"}, False, True),
    )

    def run_script(self, arguments, environment, terminal):
        """Runs the script with standard error on a pseudo-terminal or a
        pipe; its bytes.
        """
        import pty
        import subprocess

        env = {key: value for key, value in os.environ.items() if key not in COLOUR_VARIABLES}
        env.update(environment)
        if terminal:
            leader, follower = pty.openpty()
            process = subprocess.Popen([sys.executable, SCRIPT, *arguments],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=follower, env=env)
            os.close(follower)
            output = b""
            while True:
                try:
                    chunk = os.read(leader, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                output += chunk
            process.wait(10)
            os.close(leader)
            return output
        return subprocess.run([sys.executable, SCRIPT, *arguments], stdin=subprocess.DEVNULL,
                              capture_output=True, env=env, timeout=10).stderr

    def test_every_copied_message_and_exit_code_matches_its_source(self):
        """
        Compare the title, digest length, exits and all shared message
        shapes.
        """
        serve = rust_source("serve.rs").split("#[cfg(test)]")[0]
        self.assertEqual(json.loads(rust_constant(serve, "TITLE")), fast_mode.TITLE)
        self.assertEqual(int(rust_constant(serve, "SHA256_HEX_DIGITS")),
                         fast_mode.SHA256_HEX_DIGITS)
        for name in ("SUCCESS", "INTERNAL_ERROR", "INVALID_INPUT"):
            self.assertEqual(int(rust_constant(rust_source("exit.rs"), name)),
                             getattr(fast_mode, name), name)
        with open(SCRIPT, encoding="utf-8") as script:
            literals = {message_shape(node.value) for node in ast.walk(ast.parse(script.read()))
                        if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        for beginning in (
                "There is no readable", "{CHECKSUM_FILE} names", "Cannot read",
                "{} is larger than", "The SHA-256 of", "SHA-256 of {} verified",
                "Open {shown}", "Opened {shown}", "Fast mode is running.",
                "Close this window or press Ctrl+C to stop."):
            self.assertIn(message_shape(rust_string(serve, beginning)), literals,
                          beginning)
        note = rust_string(serve, "The page is served only when")
        self.assertEqual(note.replace("{CHECKSUM_FILE}", fast_mode.CHECKSUM_FILE),
                         fast_mode.HELP_NOTE)

    def test_the_style_constants_match_the_rust_launcher(self):
        # The constants the launcher copies from style.rs, read from its
        # source, so that a change
        # to either alone fails here (CORE-10).
        style = rust_source("style.rs")
        self.assertEqual(int(rust_constant(style, "TEXT_WIDTH")), fast_mode.TEXT_WIDTH)
        self.assertEqual(int(rust_constant(style, "FACT_LABEL_WIDTH")), fast_mode.FACT_LABEL_WIDTH)
        self.assertEqual(rust_constant(style, "TICK"), '"{}"'.format(fast_mode.TICK))
        self.assertEqual(rust_constant(style, "ERROR_MARK"), '"{}"'.format(fast_mode.ERROR_MARK))
        self.assertEqual(rust_constant(style, "HELP_WIDTH"), "hidden_input::DEFAULT_COLUMNS")
        self.assertEqual(int(rust_constant(rust_source("hidden_input.rs"), "DEFAULT_COLUMNS")),
                         fast_mode.HELP_WIDTH)
        for name in ("HEADING", "ACCENT", "STRONG", "MUTED", "GOOD", "BAD", "WARNING"):
            self.assertEqual(sgr(rust_constant(style, name)), getattr(fast_mode, name), name)

    def test_the_help_has_the_sections_and_safety_line_of_mhfe_serve(self):
        text = rust_source("serve.rs")
        start = text.index('"The page is served only when {CHECKSUM_FILE}')
        literal = text[start + 1:text.index('"', start + 1)]
        safety = " ".join(re.sub(r"\\\n\s*", "", literal).replace(
            "{CHECKSUM_FILE}", fast_mode.CHECKSUM_FILE).split())
        self.assertIn(safety, " ".join(fast_mode.HELP.split()))
        for section in ("Usage:", "Arguments:", "Options:", "Examples:"):
            self.assertIn("\n{}".format(section), fast_mode.HELP)
        self.assertTrue(all(len(line) <= 80 for line in fast_mode.HELP.splitlines()))

    def help_shown(self, terminal):
        """The help as argparse prints it, at a terminal that shows
        colours, with standard output on that terminal or not, as
        `terminal` says, and standard error the other way.
        """
        with mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True), \
                contextlib.redirect_stdout(Screen(terminal)), \
                contextlib.redirect_stderr(Screen(not terminal)):
            return fast_mode.Parser().format_help()

    def test_the_help_has_the_colours_of_mhfe_serve_on_a_terminal(self):
        # argparse prints the help to standard output, so that stream
        # decides (CORE-37, CORE-38):
        # bold cyan headings, cyan command and options, grey
        # placeholders and closing note, as
        # `mhfe serve --help` shows them; plain text when standard
        # output is not a terminal.
        shown, plain = self.help_shown(True), self.help_shown(False)
        self.assertEqual(plain, fast_mode.HELP)
        self.assertEqual(COLOUR_CODE.sub("", shown), fast_mode.HELP)
        for heading in ("Usage:", "Arguments:", "Options:", "Examples:"):
            self.assertIn("\n\x1b[1;36m{}\x1b[0m".format(heading), shown)
        for option in ("python3 mhfe-fast-mode.py", "--no-browser", "-h", "--help"):
            self.assertIn("\x1b[36m{}\x1b[0m".format(option), shown)
        self.assertIn("\x1b[90m[OPTIONS]\x1b[0m \x1b[90m[FILE]\x1b[0m", shown)
        self.assertTrue(shown.endswith("\x1b[1;33m{}\x1b[0m\n".format(fast_mode.SAFETY_LINE)),
            shown)
        for line in fast_mode.wrapped(fast_mode.HELP_NOTE, fast_mode.HELP_WIDTH):
            self.assertIn("\x1b[90m{}\x1b[0m\n".format(line), shown)
        declared = re.search(r'const SAFETY_LINE: &str\s*=\s*"([^"]+)"', rust_source("style.rs"))
        self.assertEqual(declared.group(1), fast_mode.SAFETY_LINE)

    def test_messages_are_marked_and_wrapped_as_mhfe_shows_them(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            fast_mode.error("There is no readable {} in {}: No such file or directory. The fast "
                            "mode serves a page only when its checksum file lies next to it; "
                            "nothing was served.".format(fast_mode.CHECKSUM_FILE, "/a/b" * 10))
            fast_mode.ok("SHA-256 of tool.html verified")
        lines = error.getvalue().splitlines()
        self.assertEqual(lines[0], "")
        self.assertTrue(lines[1].startswith("✗ Error: "), lines)
        self.assertTrue(all(line.startswith(" " * 9) for line in lines[2:-1]), lines)
        self.assertEqual(lines[-1], "✓ SHA-256 of tool.html verified")
        self.assertTrue(all(len(line) <= 78 for line in lines), lines)

    def test_a_coloured_text_wraps_where_its_plain_text_does(self):
        # Colour codes take no column (style::wrap): the running line
        # fits 78 columns on a colour
        # terminal too, with no lone "stop." under it.
        words = "Serve the page and print its address to open by hand, as mhfe serve does".split()
        painted = " ".join(fast_mode.coloured(fast_mode.MUTED, word) for word in words)
        independent = textwrap.wrap(" ".join(words), 20)
        self.assertEqual([COLOUR_CODE.sub("", line) for line in fast_mode.wrapped(painted, 20)],
                         independent)
        screen = Screen(True)
        with tempfile.TemporaryDirectory() as folder:
            page = os.path.join(folder, "tool.html")
            with open(page, "wb") as file:
                file.write(PAGE)
            with open(os.path.join(folder, fast_mode.CHECKSUM_FILE), "w",
                encoding="utf-8") as file:
                file.write("{}  tool.html\n".format(fast_mode.sha256_of(PAGE)))
            original = fast_mode.serve
            fast_mode.serve = stopped_by_ctrl_c
            try:
                with mock.patch.dict(os.environ, {"TERM": "xterm"}, clear=True), \
                        contextlib.redirect_stderr(screen):
                    self.assertEqual(fast_mode.main(["--no-browser", page]), fast_mode.CANCELLED)
            finally:
                fast_mode.serve = original
        self.assertIn("\x1b[", screen.getvalue())
        lines = [COLOUR_CODE.sub("", line) for line in screen.getvalue().splitlines()]
        running = "✓ Fast mode is running. Close this window or press Ctrl+C to stop."
        self.assertIn(running, lines)
        self.assertNotIn("stop.", [line.strip() for line in lines])
        self.assertTrue(all(len(line) <= fast_mode.TEXT_WIDTH for line in lines), lines)

    @unittest.skipIf(os.name == "nt", "the launcher never colours the Windows console")
    def test_colours_follow_the_workspace_rule(self):
        # The rule was copied from these versions; a new one may answer
        # otherwise.
        with open(os.path.join(ROOT, "Cargo.lock"), encoding="utf-8") as lock:
            locked = lock.read()
        for crate, version in (("anstream", "1.0.0"), ("anstyle-query", "1.1.5")):
            self.assertIn('name = "{}"\nversion = "{}"\n'.format(crate, version), locked,
                          "compare colours() with the new {} and this table".format(crate))
        for environment, terminal, expected in self.COLOUR_RULE_ANSWERS:
            with mock.patch.dict(os.environ, environment, clear=True):
                answer = fast_mode.colours(Screen(terminal))
            self.assertEqual(answer, expected, (environment, terminal))

    def test_colours_follow_the_environment(self):
        # The same rule through the script itself, on a pseudo-terminal
        # or a pipe.
        missing = os.path.join(tempfile.gettempdir(), "mhfe-no-such-folder", "tool.html")
        for environment, terminal, coloured in (
            ({"TERM": "xterm"}, True, True),
            ({}, True, False),
            ({"TERM": "xterm", "NO_COLOR": "1"}, True, False),
            ({"TERM": "xterm", "NO_COLOR": "1", "CLICOLOR_FORCE": "1"}, True, False),
            ({"TERM": "xterm", "CLICOLOR": "0"}, True, False),
            ({"TERM": "dumb"}, True, False),
            ({"CLICOLOR_FORCE": "1"}, False, True),
            ({"CLICOLOR_FORCE": "0"}, False, True),
            ({}, False, False),
        ):
            output = self.run_script([missing], environment, terminal)
            self.assertIn("Error:".encode(), output)
            self.assertEqual(b"\x1b[" in output, coloured, (environment, terminal, output))


def stopped_by_ctrl_c(*arguments, **options):
    """A stand-in for serve() that the person stops at once."""
    raise KeyboardInterrupt


class AcceptErrors(unittest.TestCase):
    """serve() keeps serving after a connection it could not accept,
    pausing rather than spinning, and ends only when its listener is
    closed (AUD-023-FUN003).
    """

    class StandIn:
        def __init__(self, errors):
            self.errors = list(errors)
            self.calls = []
            self.closed = False

        def settimeout(self, seconds):
            pass

        def fileno(self):
            return -1 if self.closed else 3

        def accept(self):
            self.calls.append(time.monotonic())
            if self.errors:
                raise self.errors.pop(0)
            self.closed = True
            raise OSError(9, "Bad file descriptor")

    def test_an_accept_error_does_not_end_serving(self):
        for error in (ConnectionAbortedError(103, "aborted"), ConnectionResetError(104, "reset"),
                      OSError(24, "Too many open files"), OSError(23,
                          "Too many open files in system"),
                      OSError(105, "No buffer space available"), InterruptedError(4,
                          "interrupted")):
            listener = self.StandIn([error])
            fast_mode.serve(listener, HOST, PAGE)
            self.assertEqual(len(listener.calls), 2, "{!r}: serve() looked again".format(error))
            self.assertTrue(listener.closed)

    def test_the_loop_pauses_rather_than_spins(self):
        listener = self.StandIn([OSError(24, "Too many open files")] * 3)
        fast_mode.serve(listener, HOST, PAGE)
        gaps = [later - earlier for earlier, later in zip(listener.calls, listener.calls[1:])]
        self.assertTrue(all(gap >= fast_mode.ACCEPT_ERROR_PAUSE * 0.9 for gap in gaps), gaps)


class ChecksumFile(unittest.TestCase):
    """
    The page is served only when mhfe-fast-mode.sha256 next to it names
    it with its SHA-256.
    """

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = folder.name
        self.page = os.path.join(self.folder, "tool.html")
        with open(self.page, "wb") as file:
            file.write(PAGE)
        self.digest = fast_mode.sha256_of(PAGE)

    def write_checksum_file(self, text):
        with open(os.path.join(self.folder, fast_mode.CHECKSUM_FILE), "w",
            encoding="utf-8") as file:
            file.write(text)

    def refusal(self):
        with self.assertRaises(fast_mode.Refused) as caught:
            fast_mode.load_checked_page(self.page)
        return str(caught.exception)

    def test_the_name_matches_the_rust_launcher(self):
        self.assertIn('CHECKSUM_FILE: &str = "{}"'.format(fast_mode.CHECKSUM_FILE),
                      rust_source("serve.rs"))

    def test_non_html_names_have_their_own_refusal_in_both_launchers(self):
        source = rust_source("serve.rs")
        self.assertEqual(json.loads(rust_constant(source, "HTML_SUFFIX")), fast_mode.HTML_SUFFIX)
        joined = re.sub(r"\\\n\s*", "", rust_constant(source, "NON_HTML"))
        self.assertEqual(json.loads(joined), fast_mode.NON_HTML)
        for case in SHARED_CASES["checksumFiles"]["nonHtml"]:
            self.write_checksum_file(filled(case, self.digest))
            self.assertEqual(self.refusal(),
                fast_mode.NON_HTML.format(suffix=fast_mode.HTML_SUFFIX))

    def test_serves_a_page_named_with_its_sha256(self):
        self.write_checksum_file("{}  tool.html\n".format(self.digest))
        self.assertEqual(fast_mode.load_checked_page(self.page), (PAGE, self.digest))
        # Upper-case digits are accepted too.
        self.write_checksum_file("{}  tool.html\n".format(self.digest.upper()))
        self.assertEqual(fast_mode.load_checked_page(self.page), (PAGE, self.digest))

    def test_accepts_the_text_and_binary_output_of_sha256sum(self):
        # AUD-004-FUN002: the literal output of `sha256sum --text
        # tool.html` and
        # `sha256sum --binary tool.html` (GNU coreutils) for PAGE, as in
        # serve.rs.
        digest = "a760013b4e475f909edfdcb6e7f228ecd5536cca669741ce43972ecffd5b6f6c"
        self.assertEqual(self.digest, digest)
        for line in [
            "a760013b4e475f909edfdcb6e7f228ecd5536cca669741ce43972ecffd5b6f6c  tool.html\n",
            "a760013b4e475f909edfdcb6e7f228ecd5536cca669741ce43972ecffd5b6f6c *tool.html\n",
        ]:
            self.write_checksum_file(line)
            self.assertEqual(fast_mode.load_checked_page(self.page), (PAGE, digest), repr(line))
        # Only one marker is removed: a further "*" belongs to the name,
        # which then differs.
        for line in ["{}  *tool.html\n".format(digest), "{} **tool.html\n".format(digest)]:
            self.write_checksum_file(line)
            self.assertIn("names *tool.html, not tool.html", self.refusal(), repr(line))

    def test_refuses_without_a_matching_checksum_file(self):
        self.assertIn("There is no readable mhfe-fast-mode.sha256", self.refusal())
        self.write_checksum_file("{}  tool.html\n".format("00" * 32))
        self.assertIn("but mhfe-fast-mode.sha256 expects", self.refusal())
        self.write_checksum_file("{}  other.html\n".format(self.digest))
        self.assertIn("names other.html, not tool.html", self.refusal())
        for case in SHARED_CASES["checksumFiles"]["malformed"]:
            malformed = filled(case, self.digest)
            self.write_checksum_file(malformed)
            self.assertIn("must hold exactly one line", self.refusal(), repr(malformed))
        self.assertIn("nothing was served", self.refusal())

    def test_no_message_carries_a_control_sequence(self):
        # AUD-015-SEC002, found again in this script by AUD-018: a
        # folder name with an OSC 52
        # sequence, which would set the clipboard, is shown escaped, and
        # a checksum file that names
        # a page with a control character is malformed.
        folder = os.path.join(self.folder, "x\x1b]52;c;QUFB\x07y")
        os.mkdir(folder)
        self.page = os.path.join(folder, "tool.html")
        refusal = self.refusal()
        self.assertIn("There is no readable", refusal)
        # C0, DEL and C1 alike: a test that ignored one could not fail
        # on it.
        self.assertFalse(any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in refusal),
            repr(refusal))
        self.assertIn("x\\u{1b}]52;c;QUFB\\u{7}y", refusal)
        self.page = os.path.join(self.folder, "tool.html")
        self.write_checksum_file("{}  to\x1bol.html\n".format(self.digest))
        self.assertIn("must hold exactly one line", self.refusal())

    def test_the_checksum_format_is_said_as_mhfe_serve_says_it(self):
        # The format in words, as MALFORMED in src/bin/mhfe/serve.rs
        # says it, not as a pattern
        # with two spaces that wrapping would join (AUD-023-UI009).
        source = rust_source("serve.rs")
        start = source.index('const MALFORMED: &str = "') + len('const MALFORMED: &str = "')
        literal = source[start:source.index('";', start)]
        malformed = re.sub(r"\\\n\s*", "", literal)
        self.write_checksum_file("{}\ttool.html\n".format(self.digest))
        self.assertTrue(self.refusal().endswith(malformed), self.refusal())

    def test_serves_every_shared_checksum_file_that_is_well_formed(self):
        for case in SHARED_CASES["checksumFiles"]["served"]:
            self.write_checksum_file(filled(case, self.digest))
            self.assertEqual(fast_mode.load_checked_page(self.page), (PAGE, self.digest),
                repr(case))

    def test_refuses_a_file_too_large_or_not_regular(self):
        # As in serve.rs (AUD-024-FUN005): nothing is read whole, and
        # nothing waits for a writer.
        self.write_checksum_file("{}  tool.html\n{}".format(self.digest, " " * 4096))
        self.assertIn("must hold exactly one line", self.refusal())
        checksum = os.path.join(self.folder, fast_mode.CHECKSUM_FILE)
        os.remove(checksum)
        os.mkdir(checksum)
        self.assertIn("it is not a regular file", self.refusal())
        os.rmdir(checksum)
        with open(self.page, "wb") as file:
            file.truncate(fast_mode.MAX_PAGE + 1)
        self.write_checksum_file("{}  tool.html\n".format(self.digest))
        self.assertIn("is larger than 64 MiB", self.refusal())
        if hasattr(os, "mkfifo"):
            os.remove(self.page)
            os.mkfifo(self.page)
            self.assertIn("it is not a regular file", self.refusal())

    def test_refuses_a_directory_before_the_os_refuses_opening_it(self):
        os.remove(self.page)
        os.mkdir(self.page)
        with mock.patch.object(fast_mode.os, "open", side_effect=PermissionError(
                "synthetic Windows directory denial")) as opening:
            with self.assertRaisesRegex(OSError, "it is not a regular file"):
                fast_mode.read_regular_file(self.page, fast_mode.MAX_PAGE)
        opening.assert_not_called()

    def test_rechecks_the_opened_file_after_the_path_check(self):
        directory = os.stat(self.folder)
        with mock.patch.object(fast_mode.os, "fstat", return_value=directory):
            with self.assertRaisesRegex(OSError, "it is not a regular file"):
                fast_mode.read_regular_file(self.page, fast_mode.MAX_PAGE)

    def test_an_unforeseen_error_is_said_and_keeps_its_exit_code(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error), mock.patch.object(
            fast_mode, "main", side_effect=MemoryError()
        ):
            self.assertEqual(fast_mode.run([]), fast_mode.INTERNAL_ERROR)
        self.assertIn("✗ Error: The fast mode stopped: MemoryError()", error.getvalue())

    def test_a_checksum_file_that_is_not_utf8_is_refused(self):
        with open(os.path.join(self.folder, fast_mode.CHECKSUM_FILE), "wb") as file:
            file.write(b"\xff\xfe  tool.html\n")
        self.assertIn("There is no readable", self.refusal())

    def test_a_mistyped_argument_is_shown_escaped(self):
        # argparse repeats an unknown argument; its control characters
        # reach no terminal.
        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as caught:
            fast_mode.main(["--x\x1b]52;c;QUFB\x07", "--\x9b2J"])
        self.assertEqual(caught.exception.code, fast_mode.INVALID_INPUT)
        text = error.getvalue()
        self.assertFalse(any(ord(c) < 0x20 and c != "\n" or 0x7F <= ord(c) <= 0x9F for c in text),
                         repr(text))
        self.assertIn("\\u{1b}]52;c;QUFB\\u{7}", text)

    def test_names_are_escaped_as_the_rust_launcher_escapes_them(self):
        # The same input and the same expected text as serve.rs's
        # a_shown_path_holds_no_control_
        # character, so that both launchers show a name alike.
        path = "/tmp/x\u001b]0;TITLE\u0007y/tool.html"
        expected = "/tmp/x\\u{1b}]0;TITLE\\u{7}y/tool.html"
        self.assertEqual(fast_mode.shown(path), expected)
        self.assertIn(expected.replace("\\", "\\\\"), rust_source("serve.rs"))

    def test_the_address_is_shown_whatever_the_opener_does(self):
        # An opener that starts but fails, or opens an unwanted browser,
        # still leaves the address
        # on the screen, as mhfe serve does (AUD-023-UI010).
        self.write_checksum_file("{}  tool.html\n".format(self.digest))
        for opened in (True, False):
            error = io.StringIO()
            original_open, original_serve = fast_mode.webbrowser.open, fast_mode.serve
            fast_mode.webbrowser.open = lambda address, opened=opened: opened
            fast_mode.serve = stopped_by_ctrl_c
            try:
                with contextlib.redirect_stderr(error):
                    self.assertEqual(fast_mode.main([self.page]), fast_mode.CANCELLED)
            finally:
                fast_mode.webbrowser.open, fast_mode.serve = original_open, original_serve
            self.assertIn("http://127.0.0.1:", error.getvalue(), repr(error.getvalue()))

    def test_without_arguments_the_page_next_to_the_script_is_served(self):
        original = fast_mode.__file__
        fast_mode.__file__ = os.path.join(self.folder, "mhfe-fast-mode.py")
        served = []

        def serve_once(listener, host, page, *rest):
            # What a browser gets from the server main() started, then
            # Ctrl+C (AUD-023-ARC017).
            served.append(fast_mode.respond(request("GET", "/", host) + "\r\n", host, page))
            raise KeyboardInterrupt

        original_serve = fast_mode.serve
        try:
            # No checksum file: an explanation and the invalid-input
            # exit code.
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fast_mode.main(["--no-browser"]), fast_mode.INVALID_INPUT)
                # A wrong checksum: refused before any socket is opened.
                self.write_checksum_file("{}  tool.html\n".format("00" * 32))
                self.assertEqual(fast_mode.main(["--no-browser"]), fast_mode.INVALID_INPUT)
                # The right one: the page next to the script is served.
                self.write_checksum_file("{}  tool.html\n".format(self.digest))
                fast_mode.serve = serve_once
                self.assertEqual(fast_mode.main(["--no-browser"]), fast_mode.CANCELLED)
        finally:
            fast_mode.__file__ = original
            fast_mode.serve = original_serve
        self.assertEqual(status_line(served[0]), "HTTP/1.1 200 OK")
        self.assertTrue(served[0].endswith(PAGE))


if __name__ == "__main__":
    # Each test sets the colour variables it needs; none comes from the
    # shell that runs them.
    for variable in COLOUR_VARIABLES:
        os.environ.pop(variable, None)
    unittest.main(verbosity=1)
