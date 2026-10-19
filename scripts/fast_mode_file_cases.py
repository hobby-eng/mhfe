# TOOL-01: public-file tests for the standalone Python launcher.
"""Public-file checks for the standalone launcher."""

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from fast_mode_fixture import (
    PAGE,
    SHARED_CASES,
    fast_mode,
    filled,
    request,
    rust_constant,
    rust_source,
    status_line,
    stopped_by_ctrl_c,
)


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

    @unittest.skipUnless(os.name == "posix", "POSIX symlink creation")
    def test_refuses_a_symlink_for_the_page_or_checksum(self):
        self.write_checksum_file("{}  tool.html\n".format(self.digest))
        target = os.path.join(self.folder, "public-target")
        os.rename(self.page, target)
        os.symlink(target, self.page)
        self.assertIn("it is not a regular file", self.refusal())
        os.remove(self.page)
        os.rename(target, self.page)
        checksum = os.path.join(self.folder, fast_mode.CHECKSUM_FILE)
        os.rename(checksum, target)
        os.symlink(target, checksum)
        self.assertIn("it is not a regular file", self.refusal())

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

    def test_mistyped_arguments_are_withheld(self):
        marker = "PUBLIC_SYNTHETIC_ARGUMENT_WITHHOLD"
        for arguments in (["--" + marker], ["public.html", marker],
                          ["--x\x1b]52;c;QUFB\x07", "--\x9b2J"]):
            with self.subTest(arguments=arguments):
                error, output = io.StringIO(), io.StringIO()
                with (contextlib.redirect_stderr(error),
                      contextlib.redirect_stdout(output)):
                    with self.assertRaises(SystemExit) as caught:
                        fast_mode.main(arguments)
                self.assertEqual(
                    caught.exception.code, fast_mode.INVALID_INPUT)
                text = error.getvalue()
                self.assertIn(
                    "Invalid command line; use --help for usage.", text)
                self.assertNotIn(marker, text)
                self.assertNotIn("QUFB", text)
                self.assertEqual(output.getvalue(), "")
                controls = any(ord(c) < 0x20 and c != "\n" or
                               0x7F <= ord(c) <= 0x9F for c in text)
                self.assertFalse(controls, repr(text))

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
