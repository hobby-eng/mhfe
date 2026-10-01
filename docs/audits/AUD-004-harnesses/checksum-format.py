"""Check the launcher against actual GNU sha256sum output; no KDF or secrets."""
import importlib.util
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("launcher", ROOT / "packaging/mhfe-fast-mode.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
failed = []
with tempfile.TemporaryDirectory(prefix="mhfe-aud004-checksum-") as temporary:
    folder = pathlib.Path(temporary)
    page = folder / "tool.html"
    page.write_text("<!doctype html><title>Public audit fixture</title>")
    for mode in ("--text", "--binary"):
        checksum = subprocess.check_output(["sha256sum", mode, "tool.html"], cwd=folder)
        (folder / "mhfe-fast-mode.sha256").write_bytes(checksum)
        try:
            launcher.load_checked_page(str(page))
            python_ok = True
        except launcher.Refused:
            python_ok = False
        # The native launcher is tested in a real subprocess, killed as soon as it starts.
        try:
            completed = subprocess.run(
                [str(ROOT / "target/release/mhfe"), "serve", "--no-browser", str(page)],
                capture_output=True, timeout=0.5,
            )
            native_ok = False
            diagnostic = completed.stderr.decode()
        except subprocess.TimeoutExpired as error:
            diagnostic = (error.stderr or b"").decode()
            native_ok = "Fast mode is running" in diagnostic
        print(f"{mode}: Python accepted={python_ok}, native accepted={native_ok}")
        if not python_ok or not native_ok:
            failed.append(mode)
            print(diagnostic.strip())
assert not failed, f"Valid GNU checksum modes rejected: {failed}"
