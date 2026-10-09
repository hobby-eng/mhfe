"""Tests of packaging/mhfe-fast-mode.py, the Python version of `mhfe serve`.

They check the same cases as the tests in src/bin/mhfe/serve.rs, so that both launchers behave
alike, and run a real server on a free port of 127.0.0.1. Only the standard library is used.

Usage: python3 scripts/verify-fast-mode-script.py
"""

import importlib.util
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "packaging", "mhfe-fast-mode.py")
# Loaded under a plain name, because the file name has hyphens; no bytecode is written next to it.
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("fast_mode", SCRIPT)
fast_mode = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fast_mode)

HOST = "127.0.0.1:43210"
PAGE = b"<!doctype html><title>tool</title>"


def request(method, target, host):
    return "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: test\r\n".format(method, target, host)


def status_line(reply):
    return reply.split(b"\r\n", 1)[0].decode("ascii")


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
        with open(os.path.join(os.path.dirname(SCRIPT), "..", "src", "bin", "mhfe", "serve.rs"),
                  encoding="utf-8") as source:
            rust = source.read()
        for name, value in fast_mode.SECURITY_HEADERS:
            self.assertIn('("{}", "{}")'.format(name, value), rust)
        self.assertIn("SECURITY_HEADERS: [(&str, &str); {}]".format(len(fast_mode.SECURITY_HEADERS)),
                      rust)

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

    def test_connections_beyond_the_limit_are_closed_at_once(self):
        # Every slot is taken by a client that sends nothing until its deadline.
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


class ChecksumFile(unittest.TestCase):
    """The page is served only when mhfe-fast-mode.sha256 next to it names it with its SHA-256."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = folder.name
        self.page = os.path.join(self.folder, "tool.html")
        with open(self.page, "wb") as file:
            file.write(PAGE)
        self.digest = fast_mode.sha256_of(PAGE)

    def write_checksum_file(self, text):
        with open(os.path.join(self.folder, fast_mode.CHECKSUM_FILE), "w", encoding="utf-8") as file:
            file.write(text)

    def refusal(self):
        with self.assertRaises(fast_mode.Refused) as caught:
            fast_mode.load_checked_page(self.page)
        return str(caught.exception)

    def test_the_name_matches_the_rust_launcher(self):
        with open(os.path.join(os.path.dirname(SCRIPT), "..", "src", "bin", "mhfe", "serve.rs"),
                  encoding="utf-8") as source:
            self.assertIn('CHECKSUM_FILE: &str = "{}"'.format(fast_mode.CHECKSUM_FILE), source.read())

    def test_serves_a_page_named_with_its_sha256(self):
        self.write_checksum_file("{}  tool.html\n".format(self.digest))
        self.assertEqual(fast_mode.load_checked_page(self.page), (PAGE, self.digest))
        # Upper-case digits are accepted too.
        self.write_checksum_file("{}  tool.html\n".format(self.digest.upper()))
        self.assertEqual(fast_mode.load_checked_page(self.page), (PAGE, self.digest))

    def test_accepts_the_text_and_binary_output_of_sha256sum(self):
        # AUD-004-FUN002: the literal output of `sha256sum --text tool.html` and
        # `sha256sum --binary tool.html` (GNU coreutils) for PAGE, as in serve.rs.
        digest = "a760013b4e475f909edfdcb6e7f228ecd5536cca669741ce43972ecffd5b6f6c"
        self.assertEqual(self.digest, digest)
        for line in [
            "a760013b4e475f909edfdcb6e7f228ecd5536cca669741ce43972ecffd5b6f6c  tool.html\n",
            "a760013b4e475f909edfdcb6e7f228ecd5536cca669741ce43972ecffd5b6f6c *tool.html\n",
        ]:
            self.write_checksum_file(line)
            self.assertEqual(fast_mode.load_checked_page(self.page), (PAGE, digest), repr(line))
        # Only one marker is removed: a further "*" belongs to the name, which then differs.
        for line in ["{}  *tool.html\n".format(digest), "{} **tool.html\n".format(digest)]:
            self.write_checksum_file(line)
            self.assertIn("names *tool.html, not tool.html", self.refusal(), repr(line))

    def test_refuses_without_a_matching_checksum_file(self):
        self.assertIn("There is no readable mhfe-fast-mode.sha256", self.refusal())
        self.write_checksum_file("{}  tool.html\n".format("00" * 32))
        self.assertIn("but mhfe-fast-mode.sha256 expects", self.refusal())
        self.write_checksum_file("{}  other.html\n".format(self.digest))
        self.assertIn("names other.html, not tool.html", self.refusal())
        for malformed in [
            "",
            "{} tool.html\n".format(self.digest),
            "{}*tool.html\n".format(self.digest),
            "{}\ttool.html\n".format(self.digest),
            "{0}  tool.html\n{0}  tool.html\n".format(self.digest),
            "{0}  tool.html\n{0} *tool.html\n".format(self.digest),
            "{}  tool.txt\n".format(self.digest),
            "{}  ../tool.html\n".format(self.digest),
            "{} *../tool.html\n".format(self.digest),
            "{}  tool.html\n".format(self.digest[:63]),
            "{}g *tool.html\n".format(self.digest[:63]),
            # The control-character cases of serve.rs, so that both launchers refuse them alike.
            "{}  x\x1b]0;TITLE\x07\x1b[2Jy.html\n".format(self.digest),
            "{}  x\x9b2Jy.html\n".format(self.digest),
            "{}  x\x7fy.html\n".format(self.digest),
            "{}  tool.html\x1f\n".format(self.digest),
        ]:
            self.write_checksum_file(malformed)
            self.assertIn("must hold exactly one line", self.refusal(), repr(malformed))
        self.assertIn("nothing was served", self.refusal())

    def test_no_message_carries_a_control_sequence(self):
        # AUD-015-SEC002, found again in this script by AUD-018: a folder name with an OSC 52
        # sequence, which would set the clipboard, is shown escaped, and a checksum file that names
        # a page with a control character is malformed.
        folder = os.path.join(self.folder, "x\x1b]52;c;QUFB\x07y")
        os.mkdir(folder)
        self.page = os.path.join(folder, "tool.html")
        refusal = self.refusal()
        self.assertIn("There is no readable", refusal)
        # C0, DEL and C1 alike: a test that ignored one could not fail on it.
        self.assertFalse(any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in refusal), repr(refusal))
        self.assertIn("x\\u{1b}]52;c;QUFB\\u{7}y", refusal)
        self.page = os.path.join(self.folder, "tool.html")
        self.write_checksum_file("{}  to\x1bol.html\n".format(self.digest))
        self.assertIn("must hold exactly one line", self.refusal())

    def test_a_checksum_file_that_is_not_utf8_is_refused(self):
        with open(os.path.join(self.folder, fast_mode.CHECKSUM_FILE), "wb") as file:
            file.write(b"\xff\xfe  tool.html\n")
        self.assertIn("There is no readable", self.refusal())

    def test_a_mistyped_argument_is_shown_escaped(self):
        # argparse repeats an unknown argument; its control characters reach no terminal.
        import contextlib
        import io

        error = io.StringIO()
        with contextlib.redirect_stderr(error), self.assertRaises(SystemExit) as caught:
            fast_mode.main(["--x\x1b]52;c;QUFB\x07", "--\x9b2J"])
        self.assertEqual(caught.exception.code, fast_mode.INVALID_INPUT)
        text = error.getvalue()
        self.assertFalse(any(ord(c) < 0x20 and c != "\n" or 0x7F <= ord(c) <= 0x9F for c in text),
                         repr(text))
        self.assertIn("\\u{1b}]52;c;QUFB\\u{7}", text)

    def test_names_are_escaped_as_the_rust_launcher_escapes_them(self):
        # The same input and the same expected text as serve.rs's a_shown_path_holds_no_control_
        # character, so that both launchers show a name alike.
        path = "/tmp/x\u001b]0;TITLE\u0007y/tool.html"
        expected = "/tmp/x\\u{1b}]0;TITLE\\u{7}y/tool.html"
        self.assertEqual(fast_mode.shown(path), expected)
        with open(os.path.join(os.path.dirname(SCRIPT), "..", "src", "bin", "mhfe", "serve.rs"),
                  encoding="utf-8") as source:
            self.assertIn(expected.replace("\\", "\\\\"), source.read())

    def test_without_arguments_the_page_next_to_the_script_is_served(self):
        original = fast_mode.__file__
        fast_mode.__file__ = os.path.join(self.folder, "mhfe-fast-mode.py")
        try:
            # No checksum file: an explanation and the invalid-input exit code.
            self.assertEqual(fast_mode.main(["--no-browser"]), fast_mode.INVALID_INPUT)
            # A wrong checksum: refused before any socket is opened.
            self.write_checksum_file("{}  tool.html\n".format("00" * 32))
            self.assertEqual(fast_mode.main(["--no-browser"]), fast_mode.INVALID_INPUT)
        finally:
            fast_mode.__file__ = original


if __name__ == "__main__":
    unittest.main(verbosity=1)
