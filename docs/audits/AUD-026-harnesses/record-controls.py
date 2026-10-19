import argparse
import json
import runpy
import sys
import tempfile
from pathlib import Path
if sys.flags.optimize:
    raise SystemExit('Run audit harnesses without Python optimization')
root = Path(sys.argv[1]).resolve()
work = Path(sys.argv[2]).resolve()
baseline = runpy.run_path(
    root / 'docs/audits/AUD-024-harnesses/audit-records/check_records.py'
)
args = argparse.Namespace(schema=str(
    root.parent / 'multi-chain-wallet-tools/docs/audit-report.schema.json'
))
data = {
    'schemaVersion': 1, 'auditId': 'AUD-999', 'auditNumber': 999,
    'date': '2026-10-15', 'completedUtc': '2026-10-15T00:00:00Z',
    'title': 'Synthetic gate control',
    'reviewer': {'name': None, 'model': None, 'reasoningEffort': None},
    'snapshot': {'commit': None, 'workingTree': 'synthetic'},
    'scope': [], 'checks': [], 'findings': [], 'observations': [],
    'remediation': [], 'limitations': [],
}
with tempfile.TemporaryDirectory(
    prefix='record-controls-', dir=work,
) as folder:
    audits = Path(folder)
    baseline['records'].__globals__['AUDITS'] = audits
    md = audits / 'AUD-999-2026-10-15.md'
    md.write_text(
        '# Synthetic control\n\n**Completed (UTC):** 2026-10-15\n',
        encoding='utf-8',
    )
    companion = md.with_suffix('.json')
    companion.write_text(json.dumps(data), encoding='utf-8')
    assert not baseline['check_schema'](args)
    assert not baseline['check_dates'](args)
    data['date'] = '2000-01-01'
    companion.write_text(json.dumps(data), encoding='utf-8')
    date_problems = baseline['check_dates'](args)
    data['date'] = '2026-10-15'
    data['auditId'] = 'AUD-998'
    data['auditNumber'] = 998
    companion.write_text(json.dumps(data), encoding='utf-8')
    identity_problems = (
        baseline['check_schema'](args) + baseline['check_pairs'](args)
        + baseline['check_dates'](args)
    )
    md.unlink()
    companion.write_text('{}', encoding='utf-8')
    orphan_records = list(baseline['records']())
    orphan_problems = baseline['check_schema'](args)
    print(json.dumps({
        'validPairControlPassed': True,
        'wrongJsonDateProblems': date_problems,
        'wrongAuditIdentityProblems': identity_problems,
        'orphanJsonEnumerated': len(orphan_records),
        'invalidOrphanSchemaProblems': orphan_problems,
    }, indent=2))
    failed = not date_problems or not identity_problems or not orphan_problems
    sys.exit(1 if failed else 0)
