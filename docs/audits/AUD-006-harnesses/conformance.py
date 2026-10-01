"""Compare released corpus bytes and independently replay recorded-key transcripts, without KDFs."""
import hashlib,json,os,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
SPEC=ROOT.parent/'mhfe_spec'
E=ROOT/'docs/audits/AUD-006-evidence'
sha=lambda b:hashlib.sha256(b).hexdigest()
env=os.environ.copy();env['PYTHONPATH']=str(ROOT.parent/'workingspace/aud006-python')
files=[]
for path in sorted((ROOT/'tests/fixtures/suite3-vectors').glob('*.json')):
    if path.name=='independent-verification.json': continue
    relative='vectors/suite3/'+path.name
    released=subprocess.check_output(['git','show','v0.4.0:'+relative],cwd=SPEC)
    assert path.read_bytes()==released,(path.name,'released specification mismatch')
    data=json.loads(path.read_text())
    if isinstance(data,dict) and data.get('schema')=='mhfe-suite-3-vector-v2': files.append(str(path))
assert len(files)==17
validation=ROOT/'tests/fixtures/validation-cases.json'
assert validation.read_bytes()==subprocess.check_output(['git','show','v0.4.0:vectors/suite3/validation-cases.json'],cwd=SPEC)
subprocess.run(['python3','scripts/independent-suite3.py','passwords',str(validation)],cwd=ROOT,env=env,check=True)
subprocess.run(['python3','scripts/independent-suite3.py','vector','--trust-argon2-keys',*files],cwd=ROOT,env=env,check=True)
record=json.loads((ROOT/'tests/fixtures/suite3-vectors/independent-verification.json').read_text())
historical=subprocess.check_output(['git','show','df70ca5:scripts/independent-suite3.py'],cwd=ROOT)
assert sha(historical)==record['verifier']['sha256']
for entry in record['files']:
    assert sha((ROOT/'tests/fixtures/suite3-vectors'/entry['name']).read_bytes())==entry['sha256']
    assert 'full' in entry['checks']
print('17 positive transcripts and negative-case corpus equal released v0.4.0; 54 fast cases equal released bytes.')
print('Historical full replay record binds the verifier at df70ca5; it is not a new full-cost replay.')
# Check both the source snapshot and the vendored file manifest without recalculating vectors.
snapshot=json.loads((E/'snapshot.json').read_text())
for name,digest in snapshot['sourceFiles'].items():
    if name!='docs/audits/README.md': assert sha((ROOT/name).read_bytes())==digest,name
for name,digest in snapshot['specificationFiles'].items(): assert sha((SPEC/name).read_bytes())==digest,name
entries=re.findall(r'^([a-f0-9]{64})  (.+)$',(ROOT/'vendor/phc-winner-argon2.md').read_text(),re.M)
for digest,name in entries: assert sha((ROOT/'vendor/phc-winner-argon2'/name).read_bytes())==digest,name
assert len(entries)==22
print('Reviewed source, specification and 22 vendored source files: unchanged.')
