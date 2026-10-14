"""Writes the Rust crates part of THIRD_PARTY_NOTICES.md: the licence of
every crate a release ships.

python3 scripts/third-party-licenses.py           write the part into
THIRD_PARTY_NOTICES.md
python3 scripts/third-party-licenses.py --check   fail if the committed
file is out of date
python3 scripts/third-party-licenses.py --binaries FILE ...   fail on an
unlisted std crate
python3 scripts/third-party-licenses.py --archives FILE ...   check
licences and std crates
python3 scripts/third-party-licenses.py --self-test           the checks
against made-up input

The crates are the union of `cargo tree --locked --offline -e
normal,no-proc-macro` over every release target and feature set (TREES
below). Build scripts, build dependencies and proc macros run only on
the build machine, so they are left out. The licence texts come from the
crates' sources in the local Cargo registry, as `cargo metadata` finds
them; nothing is downloaded. Run `cargo fetch --locked` first on a
machine whose registry lacks the sources of some target.

How the licence of a crate is chosen, the same for every crate: - The
licence expression is read from the crate's Cargo.toml. "A/B" is the old
way of writing "A OR B". - Every part joined by AND is required, so each
gets its own text, for example Unicode-3.0 next to MIT for
unicode-ident. - Within a part with alternatives joined by OR, MIT is
used when it is offered, otherwise Apache-2.0, otherwise the only
licence. Any other choice stops the script. - The text is the crate's
own licence file for that licence, copied unchanged, with its copyright
lines. Line endings become LF, and blank lines and spaces at the end are
dropped. - A crate that publishes no licence file gets the standard text
of its licence instead: for MIT, the SPDX text with the copyright
holders taken from the crate's `authors`; for CC0-1.0, the CC0 1.0 legal
code as another crate in the list ships it. Its entry says so. A licence
without such a rule stops the script.

Crates with byte-identical texts share one text section, so no copyright
line is ever dropped.

The Rust standard library and the crates it is built from are in every
program too, but no `cargo tree` lists them (AUD-023-BLD003). Their
section, "Rust standard library", is written by hand from the pinned
toolchain's sources. `--check` also compares it with the installed
toolchain: it must name the channel of rust-toolchain.toml and the
SHA-256 of the toolchain's own notice file, and list, in the versions
their libraries name, the crates from outside the Rust repository that
the toolchain's libraries are built from, for each release target whose
standard library is installed. It names the release targets it compared
and those it left out. `--binaries` reads programs, WebAssembly files
and release archives (a .tar.gz or .zip, with the notices they carry)
and refuses one that names, in a path of the form
/rust/deps/<crate>-<version>/ with either kind of slash, a crate that
the section does not list.
"""

# TOOL-01: Python supplies archive/TOML readers absent from Node's
# standard library.
from collections import namedtuple
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = REPO_ROOT / "THIRD_PARTY_NOTICES.md"
# The written notices for material that is not a crate come first, by
# hand; everything from this
# line on is generated. The line is HTML, so it does not show where the
# file is rendered.
MARKER = (
    "<!-- Everything below is written by scripts/third-party-licenses.py from Cargo.lock and the"
    " crates' own licence files; do not edit it by hand. -->"
)
OWN_PACKAGE = "mhfe-experimental"

# Every target a release is built for (packaging/Dockerfile.reproducible
# and
# .github/workflows/release.yml). The browser package is the wasm32
# build with `wasm`.
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

# A phrase every text of the licence contains. A file is used for a
# licence only when it
# contains the phrase, so that a file of another licence is never copied
# by mistake.
LICENCE_MARKERS = {
    "MIT": "Permission is hereby granted, free of charge",
    "Apache-2.0": "Apache License",
    "BSD-3-Clause": "Redistribution and use in source and binary forms",
    "CC0-1.0": "CC0 1.0 Universal",
    "Unicode-3.0": "UNICODE LICENSE V3",
    "Zlib": "This notice may not be removed or altered from any source distribution",
}

# The SPDX text of the MIT licence (https://spdx.org/licenses/MIT.html)
# with the year left out,
# as for example tokio's LICENSE writes it. {holders} is filled from the
# crate's `authors`.
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
    """
    A crate whose licence text this script cannot determine; nothing is
    written.
    """


def cargo(*arguments):
    return subprocess.run(
        ["cargo", *arguments], cwd=REPO_ROOT, check=True, capture_output=True, text=True
    ).stdout


def shipped_crates():
    """
    (name, version) of every crate compiled into a release, without this
    package.
    """
    crates = set()
    for target, features in TREES:
        arguments = ["tree", "--locked", "--offline", "-e", "normal,no-proc-macro"]
        arguments += ["--target", target, "--prefix", "none", "--format", "{p}"]
        if features:
            arguments += ["--features", features]
        for line in cargo(*arguments).splitlines():
            # "name vX.Y.Z", followed by " (*)" for a repeat or by the
            # path of a local package.
            match = re.match(r"^(\S+) v(\S+)", line)
            if match and match.group(1) != OWN_PACKAGE:
                crates.add((match.group(1), match.group(2)))
    return sorted(crates)


def registry_packages():
    """Metadata of every package in Cargo.lock, by (name, version). With
    every feature, so that the optional dependencies of the `wasm`
    feature are among them.
    """
    metadata = json.loads(
        cargo("metadata", "--locked", "--offline", "--all-features", "--format-version", "1")
    )
    return {(package["name"], package["version"]): package for package in metadata["packages"]}


def licence_parts(expression):
    """
    The parts joined by AND, each a list of the alternatives joined by
    OR.
    """
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
    """
    The text of the crate's own file for `licence`, or None if it ships
    none.
    """
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
    """
    The names in the crate's `authors`, without their e-mail addresses.
    """
    names = [re.sub(r"\s*<[^>]*>", "", author).strip() for author in package["authors"]]
    names = [name for name in names if name]
    if not names:
        raise Unresolved(f"{package['name']} ships no MIT text and names no authors")
    return ", ".join(names)


def resolve(crates, packages):
    """For each crate: its entry fields and the list of (licence, text,
    note) it needs.
    """
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
    # The standard CC0 text is known only once some crate has shipped
    # it.
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
        "- Every licence joined by AND is required and listed. "
        "Among licences joined by OR, MIT is",
        "  used when it is offered, otherwise Apache-2.0, otherwise the only licence.",
        "- The text is the crate's own licence file, unchanged, with its copyright lines. Where a",
        "  crate publishes no licence file, its entry says so "
        "and the standard text of its licence",
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


# The section of THIRD_PARTY_NOTICES.md on the Rust standard library,
# written by hand.
STD_HEADING = "## Rust standard library"
# A crate of the standard library in the section's list: "- `name`
# version: ...".
STD_LISTED = re.compile(r"^- `([A-Za-z0-9_-]+)` (\d+\.\d+\.\d+\S*?):", re.MULTILINE)
# A source path of a crate the standard library is built from, as rustc
# writes it into a program:
# /rust/deps/<crate>-<version>/ with forward slashes, or backslashes in
# a Windows program.
STD_PATH = re.compile(
    rb"[/\\]rust[/\\]deps[/\\]([A-Za-z0-9_.-]+?)-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)[/\\]"
)
# The toolchain's libraries that are part of the Rust repository itself,
# which the standard library
# section covers as a whole, and those of the toolchain that no program
# links: libtest and the
# proc_macro library, with the crates only they use.
STD_IN_TREE = {
    "alloc",
    "compiler_builtins",
    "core",
    "panic_abort",
    "panic_unwind",
    "proc_macro",
    "profiler_builtins",
    "rustc_std_workspace_alloc",
    "rustc_std_workspace_core",
    "rustc_std_workspace_std",
    "std",
    "std_detect",
    "sysroot",
    "test",
    "unwind",
}
STD_NOT_LINKED = {"getopts", "rustc_literal_escaper"}
# The release targets whose standard library a program or the
# WebAssembly links: those of TREES.
STD_TARGETS = tuple(target for target, _ in TREES)
# The toolchain's own notice for the standard library, under its root.
STD_NOTICE = Path("share/doc/rust/COPYRIGHT-library.html")


def crate_key(name):
    """
    A crate's name as its library file writes it: cfg-if and cfg_if are
    one crate.
    """
    return name.replace("-", "_")


def std_section(notices):
    """
    The text of the standard library section of `notices`, or None when
    it has none.
    """
    start = notices.find(f"\n{STD_HEADING}\n")
    if start < 0:
        return None
    rest = notices[start + 1 :]
    ends = [index for index in (rest.find("\n## ", 1), rest.find(MARKER)) if index >= 0]
    return rest[: min(ends)] if ends else rest


def listed_std_crates(notices):
    """
    {crate key: version} of the crates the section of `notices` lists;
    None without it.
    """
    section = std_section(notices)
    if section is None:
        return None
    return {crate_key(name): version for name, version in STD_LISTED.findall(section)}


def std_crates_named(data):
    """{(crate key, version)} named by source paths of the standard
    library's crates in `data`.
    """
    return {
        (crate_key(name.decode()), version.decode()) for name, version in STD_PATH.findall(data)
    }


# What a comparison of the standard library section with the installed
# toolchain found: what the
# section lacks, one line each, the release targets whose libraries were
# compared, and those left
# out because their standard library is not installed, so that a partial
# comparison never reads as
# a full one.
Comparison = namedtuple("Comparison", ("differences", "compared", "not_installed"))


def toolchain_comparison(notices, channel, sysroot):
    """
    The Comparison of the standard library section of `notices` with the
    toolchain `channel` installed at `sysroot`.
    """
    section = std_section(notices)
    if section is None:
        return Comparison([f"{OUTPUT.name} has no section {STD_HEADING!r}"], [], [])
    found = []
    if f"Rust {channel}" not in section:
        found.append(f"the standard library section does not name Rust {channel}")
    notice = sysroot / STD_NOTICE
    if not notice.is_file():
        found.append(f"the toolchain has no {STD_NOTICE} to compare with")
    else:
        digest = hashlib.sha256(notice.read_bytes()).hexdigest()
        if digest not in section:
            found.append(
                f"the standard library section does not give the SHA-256 {digest} of {STD_NOTICE}"
            )
    listed = listed_std_crates(notices)
    libraries = 0
    compared, not_installed = [], []
    for target in STD_TARGETS:
        folder = sysroot / "lib" / "rustlib" / target / "lib"
        if not folder.is_dir():
            not_installed.append(target)
            continue
        compared.append(target)
        for library in sorted(folder.glob("lib*.rlib")):
            name = library.name[len("lib") :].rsplit("-", 1)[0]
            if name in STD_IN_TREE or name in STD_NOT_LINKED:
                continue
            libraries += 1
            if name not in listed:
                found.append(
                    f"{target}: the standard library is built from {name}, which is not listed"
                )
                continue
            for key, version in std_crates_named(library.read_bytes()):
                if key == name and version != listed[name]:
                    found.append(f"{target}: {name} is {version}, but {listed[name]} is listed")
    if libraries == 0:
        found.append(f"no library of the standard library found under {sysroot}")
    return Comparison(found, compared, not_installed)


def pinned_toolchain():
    """
    The channel of rust-toolchain.toml and the root of that toolchain as
    rustup installed it.
    """
    with open(REPO_ROOT / "rust-toolchain.toml", "rb") as source:
        channel = tomllib.load(source)["toolchain"]["channel"]
    sysroot = subprocess.run(
        ["rustc", "--print", "sysroot"], cwd=REPO_ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()
    return channel, Path(sysroot)


def archive_files(path):
    """
    {name: bytes} of the files of a release archive, by path without a
    leading "./".
    """
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as packed:
            return {name.removeprefix("./"): packed.read(name) for name in packed.namelist()}
    with tarfile.open(path) as packed:
        return {
            member.name.removeprefix("./"): packed.extractfile(member).read()
            for member in packed.getmembers()
            if member.isfile()
        }


def unlisted_std_crates(paths, notices):
    """
    What the files at `paths` name that their notices do not list, one
    line each, and how many crates of the standard library they name in
    all. An archive is read with the notices it carries; any other file
    with `notices`.
    """
    found = []
    named = 0
    for path in paths:
        if path.endswith((".zip", ".tar.gz")):
            files = {f"{path}: {name}": data for name, data in archive_files(path).items()}
            carried = files.get(f"{path}: {OUTPUT.name}", b"").decode("utf-8")
            source = f"{path}: {OUTPUT.name}"
        else:
            files = {path: Path(path).read_bytes()}
            carried, source = notices, OUTPUT.name
        missing, count = unlisted_file_crates(files, carried, source)
        found.extend(missing)
        named += count
    return found, named


def unlisted_file_crates(files, carried, source):
    """Missing standard-library notices in already-read binary/archive
    files.
    """
    listed = listed_std_crates(carried)
    if listed is None:
        return [f"{source} has no section {STD_HEADING!r}"], 0
    found, named = [], 0
    for name, data in sorted(files.items()):
        for key, version in sorted(std_crates_named(data)):
            named += 1
            if listed.get(key) != version:
                found.append(f"{name} holds {key} {version}, which is not listed")
    return found, named


def check_archives(paths):
    """The exact project licences and complete std-crate notices in each
    archive.
    """
    found, named = [], 0
    required = ("LICENSE-MIT", "LICENSE-APACHE", OUTPUT.name)
    for path in paths:
        files = archive_files(path)
        for name in required:
            if files.get(name) != (REPO_ROOT / name).read_bytes():
                found.append(f"{path} lacks {name} or holds another version of it.")
        notices = files.get(OUTPUT.name, b"").decode("utf-8")
        missing, count = unlisted_file_crates(
            {f"{path}: {name}": data for name, data in files.items()}, notices,
            f"{path}: {OUTPUT.name}")
        found.extend(missing)
        named += count
    for line in found:
        print(line, file=sys.stderr)
    if found:
        return 1
    print(f"Every archive carries the licence files: {len(paths)} checked.")
    print(
        f"Every crate of the standard library in {len(paths)} archives "
        f"is listed ({named} paths)."
    )
    return 0


def self_test():
    """The standard library checks against made-up notices, programs and
    archives.
    """
    notices = "\n".join(
        [
            "# Notices",
            "",
            STD_HEADING,
            "",
            "- Rust 9.9.9, notice SHA-256 " + hashlib.sha256(b"notice").hexdigest() + ".",
            "- `cfg-if` 1.0.4: `MIT`.",
            "- `hashbrown` 0.17.1: `MIT`.",
            "",
            MARKER,
            "",
            "- `serde` 1.0.0: `MIT`.",
        ]
    )

    def expect(what, value, wanted):
        if value != wanted:
            sys.exit(f"self-test: {what} gives {value!r}")

    expect("the list", listed_std_crates(notices), {"cfg_if": "1.0.4", "hashbrown": "0.17.1"})
    expect("no section", listed_std_crates("# Notices\n"), None)
    program = b"/rust/deps/hashbrown-0.17.1/src/raw.rs\0\\rust\\deps\\rustc-demangle-0.1.28\\src"
    named = {("hashbrown", "0.17.1"), ("rustc_demangle", "0.1.28")}
    expect("both slashes", std_crates_named(program), named)
    with tempfile.TemporaryDirectory() as scratch:
        listed_program = Path(scratch, "listed")
        listed_program.write_bytes(b"/rust/deps/cfg-if-1.0.4/src/lib.rs")
        other_program = Path(scratch, "other")
        other_program.write_bytes(program)
        expect("a listed crate", unlisted_std_crates([str(listed_program)], notices), ([], 1))
        found, _ = unlisted_std_crates([str(other_program)], notices)
        unlisted = [f"{other_program} holds rustc_demangle 0.1.28, which is not listed"]
        expect("an unlisted crate", found, unlisted)
        archive = Path(scratch, "lacking.zip")
        with zipfile.ZipFile(archive, "w") as packed:
            packed.writestr(OUTPUT.name, "# Notices\n")
            packed.writestr("mhfe", b"/rust/deps/cfg-if-1.0.4/src/lib.rs")
        found, _ = unlisted_std_crates([str(archive)], notices)
        expect("an archive without the section", len(found), 1)
        sysroot = Path(scratch, "sysroot")
        (sysroot / STD_NOTICE).parent.mkdir(parents=True)
        (sysroot / STD_NOTICE).write_bytes(b"notice")
        libraries = sysroot / "lib" / "rustlib" / "wasm32-unknown-unknown" / "lib"
        libraries.mkdir(parents=True)
        for name, data in (
            ("std", b""),
            ("getopts", b""),
            ("cfg_if", b"/rust/deps/cfg-if-1.0.4/src"),
            ("hashbrown", b"/rust/deps/hashbrown-0.17.1/src"),
        ):
            (libraries / f"lib{name}-0123abcd.rlib").write_bytes(data)
        # Only the WebAssembly target is installed: the native ones are
        # named as not compared.
        matching = Comparison([], ["wasm32-unknown-unknown"], list(NATIVE_TARGETS))
        expect("the matching toolchain", toolchain_comparison(notices, "9.9.9", sysroot), matching)

        def differences(notices=notices, channel="9.9.9"):
            return len(toolchain_comparison(notices, channel, sysroot).differences)

        expect("another channel", differences(channel="9.9.10"), 1)
        (sysroot / STD_NOTICE).write_bytes(b"another notice")
        expect("another notice", differences(), 1)
        (sysroot / STD_NOTICE).write_bytes(b"notice")
        (libraries / "libhashbrown-0123abcd.rlib").write_bytes(b"/rust/deps/hashbrown-0.18.0/src")
        (libraries / "libdlmalloc-0123abcd.rlib").write_bytes(b"")
        expect("a new version and a new crate", differences(), 2)
        expect("no section", differences(notices="# Notices\n"), 1)
        # No release target installed: nothing compared, which fails
        # rather than passes.
        empty = Path(scratch, "empty")
        (empty / STD_NOTICE).parent.mkdir(parents=True)
        (empty / STD_NOTICE).write_bytes(b"notice")
        nothing = toolchain_comparison(notices, "9.9.9", empty)
        expect("no target installed", (len(nothing.differences), nothing.compared), (1, []))
    print("The standard library checks find every gap in their test cases.")
    return 0


def check_binaries(paths):
    """`--binaries`: refuses a file that names a crate of the standard
    library its notices lack.
    """
    found, named = unlisted_std_crates(paths, OUTPUT.read_text(encoding="utf-8"))
    for line in found:
        print(line, file=sys.stderr)
    if found:
        print(f"List them in the section {STD_HEADING!r} of {OUTPUT.name}.", file=sys.stderr)
        return 1
    print(f"Every crate of the standard library in {len(paths)} files is listed ({named} paths).")
    return 0


def check_toolchain(notices):
    """`--check`, second part: compares the standard library section of
    `notices` with the installed toolchain and says which release
    targets it compared and which it left out.
    """
    channel, sysroot = pinned_toolchain()
    comparison = toolchain_comparison(notices, channel, sysroot)
    for line in comparison.differences:
        print(line, file=sys.stderr)
    if comparison.differences:
        print(
            f"Review the section {STD_HEADING!r} of {OUTPUT.name} for Rust {channel}.",
            file=sys.stderr,
        )
        return 1
    print(
        f"{OUTPUT.name} matches the shipped crates. Its standard library section matches the "
        f"notice of the installed Rust {channel} and the crates of its libraries for "
        f"{', '.join(comparison.compared)}."
    )
    if comparison.not_installed:
        print(
            "Not compared, as their standard library is not installed: "
            f"{', '.join(comparison.not_installed)}."
        )
    return 0


def main(arguments):
    if arguments == ["--self-test"]:
        return self_test()
    if arguments[:1] == ["--binaries"] and len(arguments) > 1:
        return check_binaries(arguments[1:])
    if arguments[:1] == ["--archives"] and len(arguments) > 1:
        return check_archives(arguments[1:])
    check = arguments == ["--check"]
    if arguments and not check:
        print(__doc__, file=sys.stderr)
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
        return check_toolchain(written)
    OUTPUT.write_text(content, encoding="utf-8")
    print(f"Wrote {OUTPUT.name}.")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("CARGO_TERM_COLOR", "never")
    sys.exit(main(sys.argv[1:]))
