# AUD-006 reproduction harnesses

These scripts belong to the final MHFE code, suite 3 conformance and prepared 0.4.0
artifact review of commit `fe1823051c74ae4d7883e5f123fe77a20c6f92d4`.
See the [report](../audit-06-2026-10-01.md) for exact executed commands, outcomes,
limitations and hashes. All inputs are public fixtures or synthetic values.
No script in this folder runs full-cost Argon2 or changes production files.

Run from the MHFE repository root in the authoritative bip_tools workspace.
Use Node 26.10.0, Python with jsonschema, the repository's installed Prettier,
and the Rust/Emscripten toolchains specified in AGENTS.md. Browser tests require
Playwright and its Chromium/Firefox installations from the adjacent
multi-chain-wallet-tools checkout; browser sandboxing must be available.
The artifact tests require the six supplied canonical archives and SHA256SUMS in
canonical-output/release/. They do not download or rebuild them. The CI comparison
uses authenticated read-only `gh` access and requires that GitHub retains the run.

## Capture and ordinary checks

`run.py` captures the reviewed inventory once and records each command's exact
arguments, environment, timestamps, exit code and output hash. Existing labels
and snapshots are intentionally not overwritten. All output is local and ignored
under docs/audits/AUD-006-evidence/. Never commit that folder.

```sh
python3 docs/audits/AUD-006-harnesses/run.py capture
python3 docs/audits/AUD-006-harnesses/run.py full-check -- bash -c 'set -e; source ../workingspace/emsdk/emsdk_env.sh; export EMCC_CORES=1; scripts/check.sh; npm run format:check'
```

The report already retains a capture and full-check; do not run those commands
again over existing evidence. A fresh reproduction requires its own local
record labels and inventory. The ordinary check script skips full-cost tests.
Use the report's `old-regressions` command to rerun the earlier allocator,
CLI/checksum and launcher probes. Their inputs and instructions are retained in
AUD-004-harnesses and AUD-005-harnesses.

## Individual probes

```sh
python3 docs/audits/AUD-006-harnesses/artifacts.py
node docs/audits/AUD-006-harnesses/browser.mjs
node docs/audits/AUD-006-harnesses/formatting.mjs
python3 docs/audits/AUD-006-harnesses/ci-artifacts.py
python3 docs/audits/AUD-006-harnesses/conformance.py
node docs/audits/AUD-006-harnesses/api-contract.mjs
node docs/audits/AUD-006-harnesses/async-callback.mjs
```

- `artifacts.py` verifies checksums, clean source identity, license files and
  absence of the test-only marker. It extracts the browser inputs and one Linux
  executable into ignored evidence. Run it before browser.mjs. Expected: six
  passing archives, Linux version 0.4.0, exit 0.
- `browser.mjs` tests the actual archive client/core/workers in Chromium and
  Firefox, file and isolated loopback contexts. An audit-only wrapper substitutes
  256 KiB/one pass at the Argon2 call boundary; archive bytes are unchanged.
  Expected: 13 assertions in each context, no external requests, exit 0.
- `formatting.mjs` compares canonical Prettier output for eight JS/TS files
  changed by 1980ab4c541261920db5ecc963a6f27c65387cf8. It does not claim the whole commit is whitespace-only.
  Expected: identical normalized outputs, exit 0. It needs child-process access.
- `ci-artifacts.py` compares local archive hashes with exact-head canonical CI
  job logs (run 36865294492); it saves those logs locally. Expected: all six
  hashes identical, exit 0. It does not run Docker or publish anything.
- `conformance.py` compares corpus bytes to the adjacent specification's v0.4.0
  tag, replays all 17 positive transcripts with recorded keys, checks 33 password
  cases, the historical verifier record and 22 vendored source hashes. It checks
  the captured inventory too. Expected: all pass, exit 0. Keys are not recomputed.
- `api-contract.mjs` imports the actual client and contrasts three synchronous
  methods with the blanket Promise sentence in API.md and web/README.md.
  Expected on the reviewed commit: printed string/number/undefined return types,
  an assertion naming API.md and exit 1 (AUD-006-DOC001). After correcting the
  prose, exit 0. No worker or KDF runs.
- `async-callback.mjs` uses a stand-in worker to characterize a rejected async
  progress callback. Expected: an unhandled rejection is observed and the
  operation resolves; assertions pass, exit 0. This is an informational contract
  probe, not an expectation that production should always behave that way.

The independent verifier requires Unicode 17.0.0. `conformance.py` uses
workingspace/aud006-python for the hash-pinned unicodedata2 17.0.1 dependency.
Prepare it, when absent, using the unicodedata2 requirement and all its hashes
from scripts/independent-suite3-requirements.txt with pip --require-hashes,
--no-deps and --target ../workingspace/aud006-python. Preserve that exact
requirement in local evidence as unicode-requirements.txt; the report records
the executed install command. Do not install into system or home defaults.
The installed cryptography package is not used for a full-cost replay here.
A Unicode 16 environment must fail the verifier guard, not silently normalize
with different tables.

## Validate the retained report

```sh
python3 docs/audits/AUD-006-harnesses/validate_report.py
git diff --check
```

The validator requires this audit's original local snapshot/command records.
It validates schema, IDs, coverage, source identity, procedure and command-log
hashes, local links and ignored-evidence status, then writes report-validation.json
and SHA256SUMS locally. Expected: all assertions pass, exit 0. This validates the
retained evidence, not a replacement for executing the code probes. After any
report edit, rerun it to refresh report hashes.
