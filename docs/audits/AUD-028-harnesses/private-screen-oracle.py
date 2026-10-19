#!/usr/bin/env python3
"""Challenge the actual PTY helper with finite synthetic screen transcripts."""

import ast
from pathlib import Path
import sys


def main():
    if sys.flags.optimize:
        raise RuntimeError("The reviewed test helper requires assertions")
    root = Path(__file__).resolve().parents[3]
    package = root / "scripts/terminal_suite"
    context = {}
    constants = ast.parse((package / "constants.py").read_text())
    for statement in constants.body:
        if not isinstance(statement, ast.Assign):
            continue
        names = statement.targets[0]
        if (isinstance(names, ast.Tuple) and
                [name.id for name in names.elts] ==
                ["ENTER_PRIVATE", "LEAVE_PRIVATE"]):
            context.update(zip(
                ("ENTER_PRIVATE", "LEAVE_PRIVATE"),
                ast.literal_eval(statement.value), strict=True,
            ))
    source = package / "session.py"
    tree = ast.parse(source.read_text())
    methods = [node for node in tree.body
               if isinstance(node, ast.FunctionDef) and
               node.name == "shown_privately"]
    if len(methods) != 1 or len(context) != 2:
        raise RuntimeError("Expected the actual helper and screen markers")
    module = ast.Module(body=methods, type_ignores=[])
    exec(compile(module, str(source), "exec"), context)
    enter, leave = context["ENTER_PRIVATE"], context["LEAVE_PRIVATE"]
    secret = b"SYNTHETIC_PRIVATE_SCREEN_WORD"
    cases = [
        (enter + secret + leave, True),
        (enter + leave, False),
        (secret + enter + leave, False),
        (enter + leave + secret, False),
        (enter + secret, False),
    ]
    mismatches = []
    for number, (transcript, expected) in enumerate(cases):
        try:
            context["shown_privately"]("audit control", transcript, secret)
            passed = True
        except AssertionError:
            passed = False
        if passed != expected:
            mismatches.append(number)
    print({"cases": len(cases), "mismatches": mismatches})
    if mismatches:
        raise RuntimeError("PTY private-screen helper accepted false evidence")
    print("PASS: private-screen oracle requires the shown secret")


if __name__ == "__main__":
    main()
