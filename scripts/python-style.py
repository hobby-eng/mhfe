#!/usr/bin/env python3
"""Check the agreed PEP 8 widths using Python's own syntax tree."""

# Python's AST distinguishes a docstring from an ordinary string,
# a string containing code, a '#' or triple quotes; Node has neither.
import ast
import json
import sys


# PEP 8 permits a team's agreed code width up to 99. The owner chose 99
# for code, and 72 for comments and docstrings (AUD-024-ARC037).
CODE_WIDTH = 99
PROSE_WIDTH = 72


def findings(path, text):
    """Report wide lines, with tabs expanded to eight columns."""
    tree = ast.parse(text, filename=path)
    prose = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef,
                                 ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.body:
            continue
        first = node.body[0]
        if (isinstance(first, ast.Expr) and
                isinstance(first.value, ast.Constant) and
                isinstance(first.value.value, str)):
            prose.update(range(first.lineno, first.end_lineno + 1))
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        limit = (PROSE_WIDTH if number in prose or
                 line.lstrip().startswith("#") else CODE_WIDTH)
        width = len(line.expandtabs(8))
        if width > limit:
            found.append(
                f"TOOL-04 {path}:{number}: {width} columns, at most {limit}"
            )
    return found


if __name__ == "__main__":
    if len(sys.argv) != 1:
        sys.exit("python-style.py takes JSON sources on standard input")
    sources = json.load(sys.stdin)
    print(json.dumps([
        issue for path, text in sources.items()
        for issue in findings(path, text)
    ]))
