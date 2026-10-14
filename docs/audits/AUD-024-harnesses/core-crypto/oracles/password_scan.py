"""The specification's password rule for every Unicode scalar value, written from mhfe_spec/README.md
("Password encoding") with unicodedata2 (Unicode 17.0.0): refused if Cc or U+2028/U+2029, refused if
Cn (unassigned, noncharacters), else UTF8(NFKD(P)) with 1..1024 bytes. Same line format as the Rust
probe; prints the counts and the SHA-256 of all lines."""
import hashlib, sys
import unicodedata2 as u
assert u.unidata_version == "17.0.0"
h = hashlib.sha256(); counts = {"ok": 0, "control": 0, "unassigned": 0}
for cp in range(0x110000):
    if 0xD800 <= cp <= 0xDFFF:
        continue
    c = chr(cp); cat = u.category(c)
    if cat == "Cc" or cp in (0x2028, 0x2029):
        line = f"{cp:x} control\n"; counts["control"] += 1
    elif cat == "Cn":
        line = f"{cp:x} unassigned\n"; counts["unassigned"] += 1
    else:
        b = u.normalize("NFKD", c).encode()
        assert 1 <= len(b) <= 1024
        line = f"{cp:x} ok {b.hex()}\n"; counts["ok"] += 1
    h.update(line.encode())
print(f"accepted {counts['ok']} control {counts['control']} unassigned {counts['unassigned']} other 0")
print("sha256", h.hexdigest())
