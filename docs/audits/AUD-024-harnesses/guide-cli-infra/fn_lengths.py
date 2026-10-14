"""Lists Rust functions of the given files longer than a threshold, outside #[cfg(test)] modules.

A rough brace counter: it skips string and char literals and comments well enough for this code."""
import re, sys
threshold = int(sys.argv[1])
for path in sys.argv[2:]:
    lines = open(path, encoding="utf-8").read().split("\n")
    # Cut at the test module.
    cut = len(lines)
    for i, l in enumerate(lines):
        if l.strip() == "#[cfg(test)]" and i + 1 < len(lines) and lines[i+1].strip().startswith("mod tests"):
            cut = i
            break
    fn_re = re.compile(r"^\s*(pub(\([^)]*\))?\s+)?(const\s+)?(unsafe\s+)?(extern\s+\"C\"\s+)?fn\s+(\w+)")
    i = 0
    while i < cut:
        m = fn_re.match(lines[i])
        if m:
            name = m.group(6)
            depth = 0; started = False; j = i
            while j < cut:
                code = re.sub(r'"([^"\\]|\\.)*"', '""', lines[j])
                code = re.sub(r"//.*", "", code)
                code = re.sub(r"'(\\.|[^'\\])'", "''", code)
                for ch in code:
                    if ch == "{": depth += 1; started = True
                    elif ch == "}": depth -= 1
                if started and depth == 0:
                    break
                if not started and code.rstrip().endswith(";"):
                    break
                j += 1
            length = j - i + 1
            if started and length > threshold:
                print(f"{path}:{i+1}: fn {name}: {length} lines")
        i += 1
    print(f"{path}: {cut} lines before tests ({len(lines)} total)", file=sys.stderr)
