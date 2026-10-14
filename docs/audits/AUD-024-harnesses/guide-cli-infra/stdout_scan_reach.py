"""Replicates the scan of main.rs's test every_result_is_written_through_one_function: each file is
cut at its first "#[cfg(test)]", and only the part before it is searched for println!/print!.
Lists, for every file of src/bin/mhfe, the lines after that cut that are not inside the file's
`mod tests` module: production code the test never reads."""
import os, sys
root = sys.argv[1]
total = 0
for dirpath, _, files in sorted(os.walk(root)):
    for name in sorted(files):
        path = os.path.join(dirpath, name)
        lines = open(path, encoding="utf-8").read().split("\n")
        first = next((i for i, l in enumerate(lines) if "#[cfg(test)]" in l), None)
        if first is None:
            continue
        # The test module: "#[cfg(test)]" directly followed by "mod tests".
        module = next((i for i, l in enumerate(lines)
                       if l.strip() == "#[cfg(test)]" and i + 1 < len(lines)
                       and lines[i + 1].strip().startswith("mod tests")), len(lines))
        # hidden_input.rs puts an #[allow] between: count from the attribute block.
        for i, l in enumerate(lines):
            if l.strip().startswith("mod tests") and i < module:
                module = i
        if first < module:
            missed = module - first
            total += missed
            print(f"{os.path.relpath(path, root)}: scan stops at line {first + 1}, tests start at line {module + 1}: {missed} lines of code unscanned")
print(f"total unscanned lines: {total}")
