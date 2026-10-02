"""Writes the Rust crates part of THIRD_PARTY_NOTICES.md: the licence of every crate a release ships.

    python3 scripts/third-party-licenses.py           write the part into THIRD_PARTY_NOTICES.md
    python3 scripts/third-party-licenses.py --check   fail if the committed file is out of date

The crates are the union of `cargo tree --locked --offline -e normal,no-proc-macro` over every
release target and feature set (TREES below). Build scripts, build dependencies and proc macros
run only on the build machine, so they are left out. The licence texts come from the crates'
sources in the local Cargo registry, as `cargo metadata` finds them; nothing is downloaded. Run
`cargo fetch --locked` first on a machine whose registry lacks the sources of some target.

How the licence of a crate is chosen, the same for every crate:
- The licence expression is read from the crate's Cargo.toml. "A/B" is the old way of writing
  "A OR B".
- Every part joined by AND is required, so each gets its own text, for example Unicode-3.0 next to
  MIT for unicode-ident.
- Within a part with alternatives joined by OR, MIT is used when it is offered, otherwise
  Apache-2.0, otherwise the only licence. Any other choice stops the script.
- The text is the crate's own licence file for that licence, copied unchanged, with its copyright
  lines. Line endings become LF, and blank lines and spaces at the end are dropped.
- A crate that publishes no licence file gets the standard text of its licence instead: for MIT,
  the SPDX text with the copyright holders taken from the crate's `authors`; for CC0-1.0, the
  CC0 1.0 legal code as another crate in the list ships it. Its entry says so. A licence without
  such a rule stops the script.

Crates with byte-identical texts share one text section, so no copyright line is ever dropped.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "THIRD_PARTY_NOTICES.md"
# The written notices for material that is not a crate come first, by hand; everything from this
# line on is generated. The line is HTML, so it does not show where the file is rendered.
MARKER = (
    "<!-- Everything below is written by scripts/third-party-licenses.py from Cargo.lock and the"
    " crates' own licence files; do not edit it by hand. -->"
)
OWN_PACKAGE = "mhfe-experimental"

# Every target a release is built for (packaging/Dockerfile.reproducible and
# .github/workflows/release.yml). The browser package is the wasm32 build with `wasm`.
NATIVE_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)
TREES = [(target, "") for target in NATIVE_TARGETS]
TREES.append(("wasm32-unknown-unknown", "wasm"))

# The order in which an alternative of an OR is chosen.
PREFERRED_LICENCES = ("MIT", "Apache-2.0")

# Licence file names to look for, per licence, before the generic names.
LICENCE_FILE_NAMES = {
    "MIT": ("LICENSE-MIT", "LICENSE-MIT.md", "LICENSE-MIT.txt", "license-mit", "LICENSE.MIT"),
    "Apache-2.0": (
        "LICENSE-APACHE",
        "LICENSE-APACHE.md",
        "LICENSE-APACHE.txt",
        "license-apache-2.0",
        "LICENSE-APACHE-2.0",
    ),
    "Unicode-3.0": ("LICENSE-UNICODE",),
    "Zlib": ("LICENSE-ZLIB", "LICENSE-ZLIB.md"),
}
GENERIC_FILE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING")

# A phrase every text of the licence contains. A file is used for a licence only when it
# contains the phrase, so that a file of another licence is never copied by mistake.
LICENCE_MARKERS = {
    "MIT": "Permission is hereby granted, free of charge",
    "Apache-2.0": "Apache License",
    "BSD-3-Clause": "Redistribution and use in source and binary forms",
    "CC0-1.0": "CC0 1.0 Universal",
    "Unicode-3.0": "UNICODE LICENSE V3",
    "Zlib": "This notice may not be removed or altered from any source distribution",
}

# The SPDX text of the MIT licence (https://spdx.org/licenses/MIT.html) with the year left out,
# as for example tokio's LICENSE writes it. {holders} is filled from the crate's `authors`.
SPDX_MIT_TEXT = """MIT License

Copyright (c) {holders}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""


class Unresolved(Exception):
    """A crate whose licence text this script cannot determine; nothing is written."""


def cargo(*arguments):
    return subprocess.run(
        ["cargo", *arguments], cwd=REPO_ROOT, check=True, capture_output=True, text=True
    ).stdout


def shipped_crates():
    """(name, version) of every crate compiled into a release, without this package."""
    crates = set()
    for target, features in TREES:
        arguments = ["tree", "--locked", "--offline", "-e", "normal,no-proc-macro"]
        arguments += ["--target", target, "--prefix", "none", "--format", "{p}"]
        if features:
            arguments += ["--features", features]
        for line in cargo(*arguments).splitlines():
            # "name vX.Y.Z", followed by " (*)" for a repeat or by the path of a local package.
            match = re.match(r"^(\S+) v(\S+)", line)
            if match and match.group(1) != OWN_PACKAGE:
                crates.add((match.group(1), match.group(2)))
    return sorted(crates)


def registry_packages():
    """Metadata of every package in Cargo.lock, by (name, version). With every feature, so that
    the optional dependencies of the `wasm` feature are among them."""
    metadata = json.loads(
        cargo("metadata", "--locked", "--offline", "--all-features", "--format-version", "1")
    )
    return {(package["name"], package["version"]): package for package in metadata["packages"]}


def licence_parts(expression):
    """The parts joined by AND, each a list of the alternatives joined by OR."""
    expression = expression.replace("/", " OR ")
    parts = []
    for part in re.split(r"\s+AND\s+", expression):
        part = part.strip()
        if part.startswith("(") and part.endswith(")"):
            part = part[1:-1]
        alternatives = [alternative.strip() for alternative in re.split(r"\s+OR\s+", part)]
        if any(not re.fullmatch(r"[A-Za-z0-9.+-]+", alternative) for alternative in alternatives):
            raise Unresolved(f"licence expression {expression!r} is not a plain AND of ORs")
        parts.append(alternatives)
    return parts


def choose(alternatives):
    for preferred in PREFERRED_LICENCES:
        if preferred in alternatives:
            return preferred
    if len(alternatives) == 1:
        return alternatives[0]
    raise Unresolved(f"no rule chooses between {' OR '.join(alternatives)}")


def read_text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n").rstrip()


def licence_file_text(directory, licence):
    """The text of the crate's own file for `licence`, or None if it ships none."""
    marker = LICENCE_MARKERS.get(licence)
    if marker is None:
        raise Unresolved(f"no marker phrase is known for {licence}")
    names = LICENCE_FILE_NAMES.get(licence, ()) + GENERIC_FILE_NAMES
    for name in names:
        path = directory / name
        if path.is_file():
            text = read_text(path)
            if marker in text:
                return text
    return None


def holders(package):
    """The names in the crate's `authors`, without their e-mail addresses."""
    names = [re.sub(r"\s*<[^>]*>", "", author).strip() for author in package["authors"]]
    names = [name for name in names if name]
    if not names:
        raise Unresolved(f"{package['name']} ships no MIT text and names no authors")
    return ", ".join(names)


def resolve(crates, packages):
    """For each crate: its entry fields and the list of (licence, text, note) it needs."""
    resolved = []
    standard_texts = {}
    for name, version in crates:
        package = packages.get((name, version))
        if package is None:
            raise Unresolved(f"cargo metadata does not list {name} {version}")
        expression = package.get("license")
        if not expression:
            raise Unresolved(f"{name} {version} declares no licence expression")
        directory = Path(package["manifest_path"]).parent
        licences = []
        for alternatives in licence_parts(expression):
            licence = choose(alternatives)
            text = licence_file_text(directory, licence)
            note = None
            if text is None:
                if licence == "MIT":
                    text = SPDX_MIT_TEXT.format(holders=holders(package))
                    note = (
                        "The crate publishes no licence file. This is the standard SPDX MIT text "
                        "with the copyright holders taken from the crate's `authors`."
                    )
                elif licence == "CC0-1.0":
                    note = (
                        "The crate publishes no licence file. This is the CC0 1.0 legal code as "
                        "other crates in this list ship it."
                    )
                else:
                    raise Unresolved(f"{name} {version} ships no {licence} text")
            licences.append([licence, text, note])
            if note is None and licence == "CC0-1.0":
                standard_texts.setdefault(licence, text)
        resolved.append((name, version, expression, licences))
    # The standard CC0 text is known only once some crate has shipped it.
    for name, version, _, licences in resolved:
        for entry in licences:
            if entry[1] is None:
                if entry[0] not in standard_texts:
                    raise Unresolved(f"{name} {version}: no crate ships a {entry[0]} text to use")
                entry[1] = standard_texts[entry[0]]
    return resolved


def fence(text):
    """A code fence longer than any run of backticks in the text."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def render(resolved):
    text_numbers = {}
    text_users = {}
    for name, version, _, licences in resolved:
        for licence, text, _ in licences:
            key = (licence, text)
            if key not in text_numbers:
                text_numbers[key] = len(text_numbers) + 1
                text_users[key] = []
            text_users[key].append(f"{name} {version}")

    lines = [
        MARKER,
        "",
        "## Rust crates",
        "",
        "The `mhfe` command-line tools and the browser package of a release are compiled from",
        "the Rust crates below. Each crate is listed with its licence expression, the licence",
        "MHFE uses it under and the text of that licence. The other third-party material, the",
        "Argon2 reference code, the EFF wordlist and the JavaScript code of the browser package,",
        "is described above.",
        "",
        "### How the licence is chosen",
        "",
        "- The crates are those compiled into the program for every release target: Linux,",
        "  Windows and macOS on x86-64, Linux and macOS on ARM64, and WebAssembly with the `wasm`",
        "  feature. Build scripts and procedural macros, which run only while building, are left",
        "  out. Not every crate is in every archive.",
        "- Every licence joined by AND is required and listed. Among licences joined by OR, MIT is",
        "  used when it is offered, otherwise Apache-2.0, otherwise the only licence.",
        "- The text is the crate's own licence file, unchanged, with its copyright lines. Where a",
        "  crate publishes no licence file, its entry says so and the standard text of its licence",
        "  is used.",
        "",
        "### Crates",
        "",
    ]
    for name, version, expression, licences in resolved:
        used = " and ".join(licence for licence, _, _ in licences)
        texts = ", ".join(
            f"[text {text_numbers[(licence, text)]}](#text-{text_numbers[(licence, text)]})"
            for licence, text, _ in licences
        )
        lines.append(f"- `{name}` {version}: `{expression}`, used under {used}; {texts}.")
        for _, _, note in licences:
            if note:
                lines.append(f"  {note}")
    lines += ["", "### Licence texts", ""]
    for (licence, text), number in text_numbers.items():
        users = ", ".join(text_users[(licence, text)])
        marker = fence(text)
        lines += [f"#### Text {number}", "", f"{licence}, for {users}.", ""]
        lines += [marker, text, marker, ""]
    return "\n".join(lines)


def main(arguments):
    check = arguments == ["--check"]
    if arguments and not check:
        print("\n".join(__doc__.splitlines()[2:4]), file=sys.stderr)
        return 2
    try:
        content = render(resolve(shipped_crates(), registry_packages()))
    except Unresolved as error:
        print(f"Cannot determine a licence text: {error}. Nothing was written.", file=sys.stderr)
        return 1
    except (subprocess.CalledProcessError, FileNotFoundError) as error:
        stderr = getattr(error, "stderr", "") or ""
        print(
            f"cargo failed: {error}\n{stderr}Run `cargo fetch --locked` so that the registry "
            "holds the sources of every target.",
            file=sys.stderr,
        )
        return 1
    written = OUTPUT.read_text(encoding="utf-8") if OUTPUT.is_file() else ""
    if MARKER not in written:
        print(
            f"{OUTPUT.name} lacks the line that starts the generated part:\n{MARKER}",
            file=sys.stderr,
        )
        return 1
    content = written[: written.index(MARKER)] + content
    if check:
        if written != content:
            print(
                f"{OUTPUT.name} is out of date; run python3 scripts/third-party-licenses.py.",
                file=sys.stderr,
            )
            return 1
        print(f"{OUTPUT.name} matches the shipped crates.")
        return 0
    OUTPUT.write_text(content, encoding="utf-8")
    print(f"Wrote {OUTPUT.name}.")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("CARGO_TERM_COLOR", "never")
    sys.exit(main(sys.argv[1:]))
