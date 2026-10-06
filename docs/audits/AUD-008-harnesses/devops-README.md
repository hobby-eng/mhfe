# AUD-008 DevOps probes

These bounded probes belong to the review of MHFE commit
`01978aa01f86cbec7dbc9fb9afd131dfa1a1d650` with its captured dirty source fingerprint
`9e5357c0b085c7f68ec3c30b6940147b2aaaf89bb8f6dcbf9ea0d2d6593c790a`.
They create local evidence only and do not build, download, extract archives, modify products,
dispatch CI, sign, commit, push or publish.

Run them from the authoritative repository root with Python 3.11 or newer:

```sh
python3 docs/audits/AUD-008-harnesses/record-command.py --label devops-artifacts --timeout 30 -- python3 docs/audits/AUD-008-harnesses/devops-artifacts.py
python3 docs/audits/AUD-008-harnesses/record-command.py --label devops-static --timeout 45 -- python3 docs/audits/AUD-008-harnesses/devops-static.py
```

The recorder refuses an existing label. Choose a fresh label for a rerun; the probe JSON is the
latest summary, while the recorder preserves each command log separately.

`devops-artifacts.py` requires `docs/audits/AUD-008-evidence/snapshot.json` and the coordinator's
completed builds at `canonical-output-aud008cached/release/` and
`canonical-output-aud008uncached/release/`. It hashes all eight archives, reads members in memory,
checks the expected file allowlists, fixed archive metadata, reviewed source documentation and
launchers, dirty-source BUILD-INFO, the browser README's seven runtime digests, and absence of the
reduced-cost test marker. It checks cached versus uncached equality and verifies that the product
files in the snapshot did not change. It writes `devops-artifacts.json` under local evidence and
exits zero only when those checks pass.

`devops-static.py` requires the repository's installed locked Node tooling, Git, OpenSSH, the local
`v0.4.0` tag, and the public key `/home/sergio/.ssh/hobby-eng_signing.pub`. It checks exact direct
Cargo pins, Cargo checksum fields, Node declared/locked/installed versions and integrity fields,
external action commit pins, and version metadata. It records the release job dependencies and
the trusted prechecked branch-tag convention without treating the absence of repeated branch CI
as a product defect. It reads raw commit objects since `v0.4.0`, then verifies present SSH
signatures against a temporary allowed-signers file containing only that public key. The
temporary file is removed automatically. It writes `devops-static.json`; it exits nonzero for
missing signatures or an actual pin/integrity/verification mismatch. At the reviewed snapshot its
expected exit is 1 because seven unreleased commits are unsigned; 23 present signatures verify.
The unsigned historical v0.4.0 tag is recorded separately and is not an instruction to rewrite a
published tag.

Full-size vector replays were explicitly excluded by the owner. Native macOS and Windows
execution, ARM64 execution, remote CI state, signed release attestations, fake-Docker failure
injection, and testing a real publication are outside these probes. Build and advisory evidence
from the coordinator and other reviewers is cited as reused evidence, not independently rerun.
