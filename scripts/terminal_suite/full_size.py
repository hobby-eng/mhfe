# TOOL-01: public fixtures and cases of the Python PTY test runtime.
"""
The cases that run Argon2 at full size, 2 GiB at the default settings,
minutes each.

`mhfe encrypt --stdin --repair-words 4` writes the container and then
its card, and
`mhfe check --stdin` gives each of its three outcomes its word and exit
code. They run only with
--full (CI-04).
"""

from .constants import CONTAINER, MATCHES, NOT_VERIFIED, NO_MATCH, PHRASE, ZERO_12, ZERO_24
from .session import run_plainly


def script_encryption_writes_the_container_then_its_repair_card():
    """
    `mhfe encrypt --stdin --repair-words 4` writes exactly two lines to
    standard output, the container and then its card, as its --stdin
    help says (AUD-023-DOC001). One encryption at the default settings.
    """
    password = ZERO_12["inputs"]["password"].encode()
    lines = b"\n".join((PHRASE.encode(), password, password)) + b"\n"
    result = run_plainly(("encrypt", "--stdin", "--repair-words", "4"), lines, timeout=600)
    assert result.returncode == 0, f"encrypt --stdin --repair-words 4: {result.stderr!r}"
    written = result.stdout.decode().split("\n")
    assert written[-1] == "" and len(written) == 3, f"encrypt --stdin: {result.stdout!r}"
    assert written[0] == CONTAINER, f"encrypt --stdin: the first line is {written[0]!r}"
    assert len(written[1].split()) == 4, f"encrypt --stdin: the card is {written[1]!r}"
    print("encrypt --stdin --repair-words 4: the container, then the card, on standard output")


# Each outcome of a check in a script: its word on standard output, its
# exit code, and the reason
# on standard error (check.rs in the tool). A full recovery each: about
# a minute in a release build.
CHECK_OUTCOMES = (
    (ZERO_12, ("--words", "auto"), True, b"matches\n", MATCHES, None),
    (ZERO_24, ("--words", "auto"), True, b"not verified\n", NOT_VERIFIED,
     b"No length of 12 to 21 words passes its built-in check"),
    (ZERO_24, ("--words", "12"), False, b"does not match\n", NO_MATCH,
     b"No length's built-in check passes"),
)


def script_checks_write_the_specified_outcome_and_exit_code():
    """`mhfe check --stdin` writes the specification's word and its own
    exit code for each outcome (AUD-023-FUN002): the 12-word original
    with the length detected matches; the 24-word original with the
    length detected is not verified, as a wrong password would be; and
    with 12 stated words it does not match.
    """
    for vector, words, asks_passphrase, word, code, reason in CHECK_OUTCOMES:
        lines = [vector["container"].encode(), vector["inputs"]["password"].encode()]
        if asks_passphrase:
            lines.append(b"")
        label = f"check --stdin {' '.join(words)}, {vector['name']}"
        result = run_plainly(("check", "--stdin", *words), b"\n".join(lines) + b"\n",
                             timeout=600)
        assert (result.stdout, result.returncode) == (word, code), (
            f"{label}: {result.stdout!r}, exit code {result.returncode}")
        if reason is not None:
            assert reason in result.stderr, f"{label}: {result.stderr!r}"
    print(
        "check --stdin: matches (0), not verified (5) and does not match (3), "
        "each with its word"
    )


# The checks that run Argon2 at full size, 2 GiB at the default
# settings, minutes each: only with
# --full (CI-04).
FULL_SIZE_CHECKS = {
    "encrypt --stdin --repair-words 4 at the default settings": (
        script_encryption_writes_the_container_then_its_repair_card
    ),
    "the three outcomes of check --stdin": script_checks_write_the_specified_outcome_and_exit_code,
}
