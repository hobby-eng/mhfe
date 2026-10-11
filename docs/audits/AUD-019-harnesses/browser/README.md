# AUD-019 browser harnesses

These harnesses belong to AUD-019, MHFE 0.6.0 at reviewed commit
`66f142566464255e331763966b00ea1681c2dabd`. They use public synthetic data and the authoritative
checkouts in place. They do not run Argon2, replay vectors, build packages or launch browsers.

`inventory.py` hashes current browser sources, scripts, generated packages and the MHFE-specific
host integration; it searches candidate capabilities and decodes WASM imports and build sections.
It imports retained static helper definitions from AUD-018 without executing their main function
or reviewed code. Lexical matches require source interpretation and are not findings by themselves.
`source-bindings.py` applies the retained AUD-018 byte comparison to current AUD-019 evidence: ten
class/declaration files after build stamping and the ordered eight-piece joined worker.
Both preserve old evidence. Run them after the coordinator's source snapshot and package build:

```sh
python3 docs/audits/AUD-019-harnesses/run.py browser-source-inventory \
  python3 docs/audits/AUD-019-harnesses/browser/inventory.py
python3 docs/audits/AUD-019-harnesses/run.py browser-loader-source-bindings \
  python3 docs/audits/AUD-019-harnesses/browser/source-bindings.py
```

`rekey-retry.mjs` exercises unmodified source modules with a synthetic Worker and binding stubs.
It checks nested retry-answer wipes after cancellation or failed transfer, caller byte ownership,
replacement owner callbacks, eligible reading refusal, one recovery followed by two confirmations,
and session cleanup after success, Stop, owner refusal and binding failure. The binding stubs test
control flow, not cryptographic outputs or core validation. Its expected result is eight PASS lines
and exit zero. Two earlier audit-harness setup failures are retained separately in evidence; the
final formatted harness was rerun under a new label.

The original immutable AUD-016 `page-protocol.mjs` and `worker-cleanup.mjs` are also reused. Their
expected current results are 26 and seven PASS lines respectively and exit zero. These check
malformed envelopes, inherited handler names, explicit null secrets, caller Buffer ownership,
initialization cancellation and worker exceptional cleanup. Historical harness files are unchanged.

Run one synthetic probe at a time using Node 26.10.0 with a 128 MiB heap and the retained AUD-018
budget-readback wrapper. The example below enforces 512 MiB RSS, zero swap and a 45-second timeout;
replace `/home/user` with the local authoritative path. The transient unit needs access to the
user's systemd service manager. Give each command a fresh evidence label, and set its unit identity
consistently in `--unit` and `MHFE_BROWSER_AUDIT_UNIT`:

```sh
python3 docs/audits/AUD-019-harnesses/run.py browser-rekey-retry-current \
  systemd-run --user --wait --pipe --collect --unit=mhfe-aud019-retry \
  -p MemoryMax=512M -p MemorySwapMax=0 \
  -p WorkingDirectory=/home/user/Documents/bip_tools/mhfe \
  --setenv=MHFE_BROWSER_AUDIT_UNIT=mhfe-aud019-retry \
  bash docs/audits/AUD-018-harnesses/browser/bounded.sh \
  /home/user/.local/bin/node --max-old-space-size=128 \
  docs/audits/AUD-019-harnesses/browser/rekey-retry.mjs
```

To run the retained probes, use units `mhfe-aud019-protocol` and `mhfe-aud019-cleanup`, evidence
labels `browser-page-protocol-final` and `browser-worker-cleanup`, and script paths
`docs/audits/AUD-016-harnesses/browser/page-protocol.mjs` and
`docs/audits/AUD-016-harnesses/browser/worker-cleanup.mjs`. No high-memory operations occur.

`review-record.py` generates the local browser review and malicious-code review JSON after the
retained evidence exists. It refuses to carry changed inventoried bytes into its conclusions and
anonymizes home paths in its own outputs. It preserves original command evidence and existing
review outputs:

```sh
python3 docs/audits/AUD-019-harnesses/run.py browser-review-record \
  python3 docs/audits/AUD-019-harnesses/browser/review-record.py
```

Inputs are the current MHFE and adjacent multi-chain host sources/packages, AUD-019's
`initial-mhfe-code-manifest.txt`, retained AUD-016/AUD-018 helper files and AUD-019 command logs.
Outputs stay in ignored `docs/audits/AUD-019-evidence/browser-*` files. Exact source/helper/output
SHA-256 values, command arguments, UTC intervals and exit statuses are retained there. A host
manifest match is distinguished from signed-release admission and full host browser acceptance.

`shared-evidence.py` reconciles the coordinator's passing local package check and the fetched
tagged real-browser job log into the current review, without rerunning them. It requires the
same reviewed commit and four passing pages for the owner and fingerprint retry assertions;
it records exact UTC evidence lines, source/log hashes and the previous review hash:

```sh
python3 docs/audits/AUD-019-harnesses/run.py browser-shared-retry-evidence \
  python3 docs/audits/AUD-019-harnesses/browser/shared-evidence.py
```

These shared tests use the actual WASM and C Argon2 engine at test-only reduced cost. They close
the actual MHFE retry coverage gap while the independent synthetic probes cover exceptional
cleanup. They do not establish foreign host signed-release admission or full host acceptance.

`remediation-supplement.py` records the exact original unchecked draw-options trigger for
AUD-015-API001 and the source correction/remaining exact CSP-trigger gap for AUD-015-UI005. It
reads the original finding and retained current assertions/logs without executing target code:

```sh
python3 docs/audits/AUD-019-harnesses/run.py browser-remediation-supplement \
  python3 docs/audits/AUD-019-harnesses/browser/remediation-supplement.py
```

`report-challenge.py` retains the independent final Markdown/JSON statement challenge against
the current pair and existing source/evidence, with exact pair hashes and explicit limits. It
does not edit the reports or rerun product/signature checks. Its local output is
`docs/audits/AUD-019-evidence/report-browser-challenge.json`:

```sh
python3 docs/audits/AUD-019-harnesses/run.py browser-report-challenge \
  python3 docs/audits/AUD-019-harnesses/browser/report-challenge.py
```
