"""AUD-024 build-release harness: does a Windows release zip carry a notice for the MinGW-w64
runtime code linked into its mhfe.exe?

    python3 docs/audits/AUD-024-harnesses/build-release/mingw-runtime-notices.py ZIP [ZIP ...]

For each zip it reads mhfe.exe and THIRD_PARTY_NOTICES.md, looks in the program for texts that
only the MinGW-w64 runtime (mingw-w64-crt) writes: the pseudo-relocation error report
(crt/pseudo-reloc.c), the math error report (_matherr), the narrow and wide "(null)" of the printf
core (stdio/mingw_pformat.c) and the "Infinity" / "NaN" / "0" texts of gdtoa's dtoa. It fails (exit 1) for a zip whose program holds such
code while neither its THIRD_PARTY_NOTICES.md nor the checkout's names MinGW-w64.
"""

import pathlib
import sys
import zipfile

MARKERS = {
    "pseudo-relocation report (mingw-w64-crt crt/pseudo-reloc.c)": b"Mingw-w64 runtime failure:",
    "math error report (mingw-w64-crt _matherr)": b"_matherr(): %s in %s(%g, %g)",
    # mingw_pformat.c prints NULL strings as "(null)" in narrow and wide form, then "NaN"/"Inf".
    "printf core (mingw-w64-crt stdio/mingw_pformat.c)": b"(null)\0\0(\0n\0u\0l\0l\0)\0",
    # gdtoa's dtoa returns these three texts (nrv_alloc "Infinity", "NaN", "0").
    "gdtoa dtoa (mingw-w64-crt gdtoa/, David M. Gay, Lucent)": b"Infinity\0NaN\0" + b"0\0",
}
NOTICE_NAMES = (b"mingw-w64", b"mingw")


def names_mingw(text):
    lowered = text.lower()
    return any(name in lowered for name in NOTICE_NAMES)


def main(zips):
    if not zips:
        print(__doc__, file=sys.stderr)
        return 2
    repository = pathlib.Path(__file__).resolve().parents[4] / "THIRD_PARTY_NOTICES.md"
    checkout_names = names_mingw(repository.read_bytes())
    print(f"checkout THIRD_PARTY_NOTICES.md names MinGW-w64: {checkout_names}")
    failed = False
    for path in zips:
        with zipfile.ZipFile(path) as packed:
            program = packed.read("mhfe.exe")
            notices = packed.read("THIRD_PARTY_NOTICES.md")
        found = [what for what, marker in MARKERS.items() if marker in program]
        carried = names_mingw(notices)
        print(f"{path}: mhfe.exe {len(program)} bytes; MinGW-w64 runtime code found: "
              f"{found or 'none'}; its THIRD_PARTY_NOTICES.md names MinGW-w64: {carried}")
        if found and not carried and not checkout_names:
            print(f"FAIL {path}: MinGW-w64 runtime code without a MinGW-w64 notice")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
