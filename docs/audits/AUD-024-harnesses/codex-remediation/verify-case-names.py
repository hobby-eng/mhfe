"""
Verify renamed entry points, retained order and explicit full-cost
exclusion.
"""
import ast
import hashlib
import json
import subprocess
from pathlib import Path
source = Path('scripts/verify-hidden-input.py').read_text()
tree = ast.parse(source)
main = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main'))


def calls(node):
    return [n.value.func.id for n in node.body if isinstance(n,
            ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)]


current = calls(main)
mapping = json.loads(Path(__file__).with_name('case-renames.json').read_text())['names']
old = ast.parse(subprocess.check_output(['git', 'show',
            'ec93057c81c3c1bddc95ef71e18c27da49164688:scripts/verify-hidden-input.py'], text=True))
oldmain = next((n for n in old.body if isinstance(n, ast.FunctionDef) and n.name == 'main'))
expected = [mapping.get(name, name) for name in calls(oldmain)]
filtered = [name for name in current if name in expected]
assert filtered == expected, (filtered, expected)
assert not any((name.startswith('check_') for name in current)), current
modules = {}
for path in Path('scripts/terminal_suite').glob('*.py'):
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.FunctionDef):
            modules[node.name] = path
for name in current:
    assert name in modules, name
assert all((len(ast.parse(modules[name].read_text()).body) > 0 for name in current))
assert 'if FULL:' in source and '--full' in Path('scripts/terminal_suite/constants.py').read_text()
full = ast.parse(Path('scripts/terminal_suite/full_size.py').read_text())
full_names = [n.id for n in ast.walk(full) if isinstance(n, ast.Name) and n.id in mapping.values()]
assert len(full_names) == 2, full_names
print(len(current), (
        'fast case calls have behaviour names; all or'
        'iginal HEAD calls retain their order.'
    ))
print('The two full-cost cases remain conditional on --full:', ', '.join(full_names))
print('Runner SHA-256:', hashlib.sha256(source.encode()).hexdigest())
