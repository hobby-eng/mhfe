"""Compare the supplied archives to checksums printed by exact-commit canonical CI."""
import json,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
E=ROOT/'docs/audits/AUD-006-evidence'
runs=json.loads((E/'ci-6b349ce.json').read_text())['workflow_runs']
run=next(r for r in runs if r['name']=='CI')
assert run['head_sha']==subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
jobs=json.loads((E/f"jobs-{run['id']}.json").read_text())['jobs']
job=next(j for j in jobs if j['name']=='canonical-build')
assert job['conclusion']=='success'
log=subprocess.check_output(['gh','run','view',str(run['id']),'--repo','hobby-eng/mhfe','--job',str(job['id']),'--log'],text=True)
(E/'canonical-ci.log').write_text(log)
found={name:digest for digest,name in re.findall(r'\b([a-f0-9]{64})  (mhfe-v0\.4\.0-[^\s]+)',log)}
expected={name:digest for digest,name in (line.split('  ',1) for line in (ROOT/'canonical-output/release/SHA256SUMS').read_text().splitlines())}
assert len(found)==6,(len(found),found)
assert found==expected,{'ci':found,'local':expected}
print('All six local archives are byte-identical to exact-commit CI canonical-build checksums.')
print(run['html_url']); print(json.dumps(found,indent=2))
