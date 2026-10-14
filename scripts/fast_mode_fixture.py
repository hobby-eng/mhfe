# TOOL-01: public fixtures for the standalone Python launcher's tests.
"""Load the launcher once and read its Rust counterpart for parity."""
import importlib.util
import io
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..")
SCRIPT = os.path.join(ROOT, "packaging", "mhfe-fast-mode.py")
# Loaded under a plain name, because the file name has hyphens; no
# bytecode is written next to it.
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("fast_mode", SCRIPT)
fast_mode = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fast_mode)

HOST = "127.0.0.1:43210"
PAGE = b"<!doctype html><title>tool</title>"
# The cases both launchers must decide alike; src/bin/mhfe/serve.rs
# reads them too.
with open(os.path.join(ROOT, "tests", "fixtures", "fast-mode-cases.json"),
    encoding="utf-8") as _file:
    SHARED_CASES = json.load(_file)


def filled(case, digest):
    """
    A shared case with the page's `digest` and the address served in it.
    """
    return case.replace("{digest63}", digest[:63]).replace("{digest}",
        digest).replace("{host}", HOST)
# The variables that decide colours (anstream); each test sets the ones
# it needs.
COLOUR_VARIABLES = ("NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "TERM", "CI")
# A colour code, as the launcher and mhfe write them.
COLOUR_CODE = re.compile("\x1b\\[[0-9;]*m")
# The SGR foreground codes of anstyle's AnsiColor: 30 to 37, and 90 to
# 97 for the bright ones
# (ECMA-48 and the aixterm extension).
ANSI_COLOURS = {
    name: code
    for code, name in enumerate(
        ("Black", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "White"), 30
    )
}
ANSI_COLOURS.update({"Bright" + name: code + 60 for name, code in list(ANSI_COLOURS.items())})


def rust_source(name):
    """The text of src/bin/mhfe/`name`, a module of the mhfe program."""
    with open(os.path.join(ROOT, "src", "bin", "mhfe", name), encoding="utf-8") as source:
        return source.read()


def rust_constant(text, name):
    """
    The value of the Rust constant `name` in `text`, as written there.
    """
    # A quoted sentence can contain a semicolon; its terminator is
    # outside the string.
    pattern = r'const {}: [^=]+= ("(?:\\.|[^"\\])*"|[^;]+);'.format(name)
    return re.search(pattern, text, re.DOTALL).group(1)


def rust_string(text, beginning):
    """The Rust string that begins with `beginning`, with continuations
    joined.
    """
    literals = re.findall(r'"(?:\\.|[^"\\])*"', text, re.DOTALL)
    literal = next(value for value in literals if value[1:].startswith(beginning))
    return json.loads(re.sub(r"\\\n\s*", "", literal))


def message_shape(text):
    """
    A format string with named and positional slots represented alike.
    """
    return re.sub(r"\{[^{}]*\}", "{}", text)


def sgr(style):
    """The SGR code of an anstyle Style as style.rs writes it, such as
    "1;36" for `AnsiColor::Cyan.on_default().bold()`.
    """
    found = re.fullmatch(r"(?:AnsiColor::(\w+)\.on_default\(\)|Style::new\(\))(\.bold\(\))?",
        style)
    if found is None:
        raise ValueError("not a style of style.rs: {}".format(style))
    colour, bold = found.groups()
    return ";".join((["1"] if bold else []) + ([str(ANSI_COLOURS[colour])] if colour else []))


class Screen(io.StringIO):
    """
    Text written to a stream that is a terminal, or not, as `terminal`
    says.
    """

    def __init__(self, terminal):
        super().__init__()
        self.terminal = terminal

    def isatty(self):
        return self.terminal


def request(method, target, host):
    return "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: test\r\n".format(method, target, host)


def status_line(reply):
    return reply.split(b"\r\n", 1)[0].decode("ascii")
