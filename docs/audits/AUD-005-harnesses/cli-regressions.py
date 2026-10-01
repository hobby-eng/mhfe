"""Bounded CLI input regressions and concurrent checksum refresh; never executes Argon2."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
BINARY = str(ROOT / "target/release/mhfe")
CASES = [
    (["encrypt", "--mem", "22", "--stdin"], b"", b"memory level"),
    (["decrypt", "--pim", "1024", "--stdin"], b"", b"PIM"),
    (["decrypt", "--words", "13", "--stdin"], b"", b"phrase length"),
    (["check", "--words", "24", "--stdin"], b"", b"no built-in check"),
    (["encrypt", "--stdin"], b"public-sentinel-wrong-phrase\n", b"not a valid"),
]
for arguments, data, expected in CASES:
    result = subprocess.run([BINARY, *arguments], input=data, capture_output=True, timeout=3)
    assert result.returncode == 2, (arguments, result.stderr)
    assert expected in result.stderr, (arguments, result.stderr)
    assert not result.stdout and b"public-sentinel-wrong-phrase" not in result.stderr
    print("refused before computation:", " ".join(arguments))

with tempfile.TemporaryDirectory(prefix="mhfe-aud005-checksums-") as temporary:
    folder = Path(temporary)
    names = []
    for path in sorted((ROOT / "tests/fixtures/suite3-vectors").glob("*.json")):
        content = json.loads(path.read_text())
        if path.name == "negative-cases.json" or isinstance(content, dict) and content.get("schema") == "mhfe-suite-3-vector-v2":
            (folder / path.name).write_bytes(path.read_bytes())
            names.append(path.name)
    assert len(names) == 18
    # No vector name matches this selector: only the existing files' hashes are refreshed.
    processes = [subprocess.Popen([BINARY, "test-vectors", "--output", temporary,
        "--only", "AUD005-NO-VECTOR-MATCH"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(4)]
    for process in processes:
        out, err = process.communicate(timeout=5)
        assert process.returncode == 0, err
        assert b"Wrote 0 files" in err + out
    expected = {name: hashlib.sha256((folder / name).read_bytes()).hexdigest() for name in names}
    lines = (folder / "SHA256SUMS").read_text().splitlines()
    actual = {line.split("  ")[1]: line.split("  ")[0] for line in lines}
    assert len(lines) == 18 and actual == expected
    print("four concurrent no-KDF checksum refreshes: 18 exact entries, no duplicates or truncation")
