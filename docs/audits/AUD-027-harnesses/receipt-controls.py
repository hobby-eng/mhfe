"""
Exercise AUD-027 receipt refusals against synthetic and generated
artifacts.

TOOL-01: use the same standard-library archive readers as the audit
harness.
No source checkout or browser build is copied or modified.
"""

import gzip
import hashlib
import json
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import warnings
import zipfile


def require(condition, message):
    """Remain fail-closed under -O and -OO."""
    if not condition:
        raise ValueError(message)


def refused(operation, expected):
    """
    Require the intended refusal, not an arbitrary execution failure.
    """
    try:
        operation()
    except ValueError as error:
        require(str(error) == expected, f"Unexpected refusal: {error}")
        return
    raise ValueError(f"A negative control was accepted: {expected}")


def tar_fixture(path, entries):
    """
    Create only public synthetic tar inputs, including duplicate
    members.
    """
    with tarfile.open(path, "w:gz") as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


def zip_fixture(path, entries):
    """Retain duplicate fixture entries to challenge the name check."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                archive.writestr(name, data)


def main():
    """
    Run fixed-oracle catalog, payload, licence and budget controls.
    """
    if len(sys.argv) != 2:
        raise SystemExit("usage: receipt-controls.py <scratch folder>")
    harness = Path(__file__).with_name("canonical-receipt.py")
    digest = hashlib.sha256(harness.read_bytes()).hexdigest()
    print(json.dumps({"harnessSha256": digest}), flush=True)
    spec = importlib.util.spec_from_file_location("receipt", harness)
    receipt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(receipt)
    # Literal counts protect against deleting catalog entries together.
    require(len(receipt.BROWSER_FILES) == 17,
            "Expected the reviewed 17 files.")
    require(len(receipt.LICENSES) == 4,
            "Expected four reviewed licence texts.")
    folder = Path(sys.argv[1])
    folder.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=folder) as tmp:
        tar_path = Path(tmp) / "browser.tar.gz"
        zip_path = Path(tmp) / "windows.zip"
        browser = [(name, (Path("dist") / name).read_bytes())
                   for name in sorted(receipt.BROWSER_FILES)]
        browser += [(name, Path(source).read_bytes())
                    for name, source in receipt.BROWSER_COMMON.items()]
        browser.append(("BUILD-INFO.txt", b"synthetic public build info\n"))
        tar_fixture(tar_path, browser)
        require(len(receipt.browser_receipt(tar_path)) == 17,
                "Positive tar failed.")
        changed = [(name, b"changed" if name == "README.md" else data)
                   for name, data in browser]
        tar_fixture(tar_path, changed)
        refused(lambda: receipt.browser_receipt(tar_path),
                "A browser payload differs.")
        tar_fixture(tar_path, [(n, d) for n, d in browser if n != "README.md"])
        refused(lambda: receipt.browser_receipt(tar_path),
                "A browser payload is missing.")
        tar_fixture(tar_path, browser + [browser[0]])
        refused(lambda: receipt.browser_receipt(tar_path),
                "The browser archive repeats a member.")
        # Bound the decompressed bytes, even when payloads compress very
        # well.
        with gzip.open(tar_path, "wb") as stream:
            stream.write(b"\0" * (receipt.ARCHIVE_BYTES + 1))
        refused(lambda: receipt.browser_receipt(tar_path),
                "The tar exceeds the inspection budget.")
        texts = [(name, Path(source).read_bytes())
                 for name, source in receipt.LICENSES.items()]
        texts.append(("BUILD-INFO.txt", b"synthetic public build info\n"))
        zip_fixture(zip_path, texts)
        require(len(receipt.windows_receipt(zip_path)[0]) == 4,
                "Positive ZIP failed.")
        zip_fixture(zip_path, [
            (n, b"changed" if n == "LICENSE-MIT" else d) for n, d in texts
        ])
        refused(lambda: receipt.windows_receipt(zip_path),
                "A licence differs.")
        zip_fixture(zip_path, [(n, d) for n, d in texts if n != "LICENSE-MIT"])
        refused(lambda: receipt.windows_receipt(zip_path),
                "A required Windows text is missing.")
        zip_fixture(zip_path, [("LICENSE-MIT", b"bad first")] + texts)
        refused(lambda: receipt.windows_receipt(zip_path),
                "The Windows archive repeats a member.")
        zip_fixture(zip_path, [
            (n, b"x" * (receipt.TEXT_BYTES + 1)
             if n == "BUILD-INFO.txt" else d) for n, d in texts
        ])
        refused(lambda: receipt.windows_receipt(zip_path),
                "A Windows text exceeds the inspection budget.")
    require(hashlib.sha256(harness.read_bytes()).hexdigest() == digest,
            "The imported harness changed during controls.")
    print("PASS: 2 positive archives; 8 exact refusal controls; "
          + "Python optimize=" + str(sys.flags.optimize))


if __name__ == "__main__":
    main()
