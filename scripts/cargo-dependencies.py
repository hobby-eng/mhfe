# TOOL-01: Python provides the standard TOML parser.
"""Read Cargo dependency tables with Python's standard TOML parser.

The Node code-rules gate passes a manifest on stdin and reads JSON on
stdout. Python supplies tomllib, so no parser dependency or network
access is needed.
"""

import json
import sys
import tomllib


def dependencies(manifest):
    """List every dependency kind and target after TOML resolves key
    syntax.
    """
    sections = [("", manifest)]
    sections.extend((f"target.{name}.", table) for name, table in manifest.get("target",
        {}).items())
    found = []
    for prefix, table in sections:
        for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, value in table.get(kind, {}).items():
                version = value if isinstance(value, str) else value.get("version")
                found.append({"name": name, "section": prefix + kind, "version": version})
    return found


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("Usage: cargo-dependencies.py < Cargo.toml")
    json.dump(dependencies(tomllib.loads(sys.stdin.read())), sys.stdout)
    sys.stdout.write("\n")
