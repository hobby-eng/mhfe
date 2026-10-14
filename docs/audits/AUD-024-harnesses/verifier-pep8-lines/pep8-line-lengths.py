"""AUD-024 verifier probe (TOOL-04, PEP 8 "Maximum Line Length").

Reads every tracked Python file outside docs/audits/ from the commit given on the command line
(git show, not the working tree) and counts, in characters:
  - lines over 79 and over 99 (PEP 8: 79, or up to 99 by team agreement),
  - comment-only lines and docstring lines over 72 (PEP 8: comments and docstrings at 72,
    also under the 99 allowance),
  - inline comments whose line is over 79 (reported apart, since PEP 8's 72 is for flowing text),
  - lines over 79 whose only excess is a URL (pycodestyle exempts a lone-URL comment line).
Exits 1 when any line breaches the 99/72 limits, 0 otherwise. Run from the mhfe root.
"""
import ast
import io
import subprocess
import sys
import tokenize

commit = sys.argv[1]
names = subprocess.run(["git", "ls-tree", "-r", "--name-only", commit], check=True,
                       capture_output=True, text=True).stdout.split("\n")
files = [n for n in names if n.endswith(".py") and not n.startswith("docs/audits/")]
tot = dict(files=0, lines=0, o79=0, o99=0, o100=0, cmt72=0, doc72=0, inl=0, url=0)
rows = []
for name in files:
    text = subprocess.run(["git", "show", f"{commit}:{name}"], check=True,
                          capture_output=True).stdout.decode("utf-8")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    tot["files"] += 1
    tot["lines"] += len(lines)
    comment_only = set()
    inline = set()
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type == tokenize.COMMENT:
            row = tok.start[0]
            if lines[row - 1].lstrip().startswith("#"):
                comment_only.add(row)
            else:
                inline.add(row)
    doc_rows = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                doc_rows.update(range(body[0].lineno, body[0].end_lineno + 1))
    f = dict(o79=0, o99=0, o100=0, cmt72=0, doc72=0, inl=0, url=0, longest=(0, 0))
    for i, line in enumerate(lines, 1):
        n = len(line)
        if n > f["longest"][0]:
            f["longest"] = (n, i)
        if n > 79:
            f["o79"] += 1
            if "http://" in line or "https://" in line:
                f["url"] += 1
            if i in inline:
                f["inl"] += 1
        if n > 99:
            f["o99"] += 1
        if n > 100:
            f["o100"] += 1
        if i in comment_only and n > 72:
            f["cmt72"] += 1
        if i in doc_rows and n > 72:
            f["doc72"] += 1
    for k in ("o79", "o99", "o100", "cmt72", "doc72", "inl", "url"):
        tot[k] += f[k]
    rows.append((name, len(lines), f))
print(f"commit {commit}; Python files outside docs/audits/: {tot['files']}, lines: {tot['lines']}")
print("file | lines | >79 | >99 | >100 | comment-only >72 | docstring >72 | inline-comment >79"
      " | >79 with URL | longest (chars at line)")
for name, n, f in rows:
    print(f"{name} | {n} | {f['o79']} | {f['o99']} | {f['o100']} | {f['cmt72']} | {f['doc72']} |"
          f" {f['inl']} | {f['url']} | {f['longest'][0]} at {f['longest'][1]}")
print(f"TOTAL | {tot['lines']} | {tot['o79']} | {tot['o99']} | {tot['o100']} | {tot['cmt72']} |"
      f" {tot['doc72']} | {tot['inl']} | {tot['url']}")
sys.exit(1 if tot["o99"] or tot["cmt72"] or tot["doc72"] else 0)
