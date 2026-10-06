# AUD-008 documentation probes

These read-only probes support CHECK-DOC-001, CHECK-DOC-002 and CHECK-DOC-003 at
MHFE commit `b6993bb1c11834a01847d1812b31a24145ab1f18` plus the source fingerprint
`9e5357c0b085c7f68ec3c30b6940147b2aaaf89bb8f6dcbf9ea0d2d6593c790a`.
The reviewed specification is the local companion checkout recorded in
the audit's ignored, local `snapshot.json`.

Run from the MHFE checkout with Python 3:

```sh
python3 docs/audits/AUD-008-harnesses/record-command.py --label doc-static --timeout 60 -- python3 docs/audits/AUD-008-harnesses/doc-static-probe.py
```

The probe requires the audit snapshot, the browser package already built in
`dist/`, and the current production debug CLI in `target/debug/mhfe`. It checks
the reviewed file hashes, selected relative Markdown links at their source and
package destinations, stale source-profile statements, the repair rejection
promise, and eleven command help screens. It prints JSON lines with results and
source/artifact hashes. It performs no Argon2 work and writes no source files.
Exit 1 records the three known documentation defects; exit 2 means the source
binding differs; exit 0 means those checks pass. The input-visibility phrase in
main help is recorded separately for coordinator judgement.

The separately retained `doc-private-reporting` and
`doc-private-reporting-host` records query only the current read-only GitHub
private vulnerability reporting `enabled` boolean. The first failed at the
sandbox's network boundary; the host query returned `true`. No message,
advisory, workflow run or repository setting was changed.

Documentation review also reuses the crypto reviewer's production repair probe
and the coordinator's AUD-007 report/evidence validator logs. Those executions
are not repeated or counted again. Evidence lives only in the ignored local
`docs/audits/AUD-008-evidence/` directory.

Validate this review's JSON keys, local evidence links and final source binding:

```sh
python3 docs/audits/AUD-008-harnesses/record-command.py --label doc-review-validation --timeout 30 -- python3 docs/audits/AUD-008-harnesses/doc-validate-review.py
```

It reads `documentation-review.json`, checks the three low findings and their
local evidence references, and exits 0 on success. This scoped validation does
not replace the coordinator's schema/Markdown/index validation of the final
AUD-008 report.
