"""Check supplied canonical archives without rebuilding or running a full-cost operation."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / 'docs/audits/AUD-006-evidence'
FOLDER = ROOT / 'canonical-output/release'
sha = lambda data: hashlib.sha256(data).hexdigest()
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
entries = [line.split('  ', 1) for line in (FOLDER / 'SHA256SUMS').read_text().splitlines()]
assert len(entries) == 6 and len({name for _, name in entries}) == 6
assert {name for _, name in entries} == {p.name for p in FOLDER.iterdir() if p.suffix in ('.gz', '.zip')}
records = []
for expected, name in entries:
    path = FOLDER / name
    assert sha(path.read_bytes()) == expected, name
    if name.endswith('.zip'):
        with zipfile.ZipFile(path) as archive:
            members = {n.removeprefix('./'): archive.read(n) for n in archive.namelist() if not n.endswith('/')}
    else:
        with tarfile.open(path) as archive:
            members = {m.name.removeprefix('./'): archive.extractfile(m).read() for m in archive if m.isfile()}
    for required in ['LICENSE', 'THIRD_PARTY_NOTICES.md', 'THIRD_PARTY_LICENSES.md']:
        assert members[required] == (ROOT / required).read_bytes(), (name, required)
    assert 'Copyright (c) 2017 Clark Moody' in members['THIRD_PARTY_LICENSES.md'].decode()
    info = members['BUILD-INFO.txt'].decode()
    assert f'source: {commit} (clean)' in info, (name, info)
    assert 'mhfe v0.4.0' in info and 'rustc 1.98.1' in info
    assert all(b'MHFE-TEST-ONLY-REDUCED-ARGON2-COST' not in data for data in members.values())
    if 'browser' in name:
        assert members['client.js'] == (ROOT/'web/client.js').read_bytes()
        expected_files = re.findall(r'^([a-f0-9]{64})  (.+)$', members['README.md'].decode(), re.M)
        assert len(expected_files) >= 6
        for digest, file in expected_files:
            assert sha(members[file]) == digest, (name, file)
        dest = EVIDENCE/'browser-package'; dest.mkdir(exist_ok=True)
        for file in ['client.js','mhfe-worker.js','argon2-mt.js','argon2-st.js','mhfe_core_bg.wasm']:
            (dest/file).write_bytes(members[file])
    if name.endswith('linux-x86_64.tar.gz'):
        binary = EVIDENCE/'canonical-mhfe'; binary.write_bytes(members['mhfe']); binary.chmod(0o700)
        result=subprocess.check_output([str(binary),'--version'],text=True)
        assert result.strip() == 'mhfe 0.4.0',result
        print('Actual archived native binary:',result.strip())
    records.append({'name':name,'sha256':expected,'buildInfo':info,'members':{n:sha(v) for n,v in members.items()}})
    print(name, 'checksum, source identity, notices, test-marker exclusion: passed')
(EVIDENCE/'artifacts.json').write_text(json.dumps(records,indent=2)+'\n')
