# AUD-018 browser remediation probes and static review

This wrapper supports AUD-018 at dirty HEAD `3c60594479302827fe40975b04fd07f9f6fd4b3b`.
The coordinator's source/code fingerprints and per-file hashes identify the reviewed remediation
bytes. It reruns the unchanged AUD-016 `page-protocol.mjs` and `worker-cleanup.mjs` harnesses.
The page probe challenges malformed replies, explicit-null arguments, inherited handlers,
cancellation and caller byte ownership. The cleanup probe injects binding exceptions and checks
request overwriting and session disposal. Neither probe runs Argon2 or vector replays.

`bounded.sh` runs inside a transient user systemd unit with `MemoryMax=512M` and
`MemorySwapMax=0`. It reads both limits back before running the supplied command, applies a
45-second timeout, records the unit's peak/current memory and preserves the command exit code.
Node uses a separate 128 MiB JavaScript heap limit. Run from the mhfe checkout with Node.js
26.10.0 and the coordinator's evidence runner; no dependency or source modification is needed.

For the page probe, use a fresh transient unit and evidence label:

```sh
python3 docs/audits/AUD-018-harnesses/run.py browser-page-protocol systemd-run --user --wait --pipe --collect --unit=mhfe-aud018-protocol --property=MemoryMax=512M --property=MemorySwapMax=0 --setenv=MHFE_BROWSER_AUDIT_UNIT=mhfe-aud018-protocol --working-directory=/home/user/Documents/bip_tools/mhfe bash docs/audits/AUD-018-harnesses/browser/bounded.sh node --max-old-space-size=128 docs/audits/AUD-016-harnesses/browser/page-protocol.mjs
```

Use the actual checkout path when executing; the example anonymizes it for publication. For the
cleanup probe, change the label to `browser-worker-cleanup`, the unit/environment identity to
`mhfe-aud018-cleanup`, and the final path to `AUD-016-harnesses/browser/worker-cleanup.mjs`.
The runner refuses reused labels. Expected current results are 26/26 page assertions and 7/7
cleanup assertions, exit 0. Legacy comments describing AUD-016 baseline failures are historical.

These focused counts do not replace the coordinator's fresh package and complete native browser
checks. Full-size vector replays are excluded at the user's explicit instruction. Results bind
runtime triggers to current dirty source bytes; formal finding closure requires a fix commit.

## Source-only malicious-code review

`static-malicious-scan.py` records the browser review's file hashes, lexical matches, current Git
status and tracked diffs against HEAD. It reads MHFE's `web/`, scripts, fast-mode launcher and
fresh `dist/`, plus the MHFE integration and vendored package in the adjacent
`multi-chain-wallet-tools` checkout. The host builder and provenance files are included for their
MHFE portions; this is not a review of the whole host application. The scanner decodes WASM
import/custom sections and the embedded Argon2 modules as bytes. It never loads, compiles or
executes reviewed JavaScript or WASM, opens a browser, or runs Argon2 or vectors.

Run from the reviewed mhfe checkout with Python 3 and a fresh evidence label:

```sh
python3 docs/audits/AUD-018-harnesses/run.py browser-malicious-static-final python3 docs/audits/AUD-018-harnesses/browser/static-malicious-scan.py browser-malicious-static-final
```

Both the runner and scanner preserve existing labels; choose a new label to repeat the scan.
At the recorded dirty source bytes, the final scan inventories 120 files and six WASM import
surfaces. Every in-scope MHFE source hash matches the coordinator's AUD-018 snapshot, both
packages match their manifest-listed files, and the Python launcher equals its source. Lexical
matches include comments, documentation, fixtures and local tooling and need human review; their
count is not a security verdict. No malformed module or unmatched listed file is expected.

`loader-source-bindings.py` compares the 10 fresh class/declaration files with their source and
the worker with the ordered join of its eight local pieces, allowing only the documented build
stamp substitution:

```sh
python3 docs/audits/AUD-018-harnesses/run.py browser-loader-source-binding python3 docs/audits/AUD-018-harnesses/browser/loader-source-bindings.py
```

The expected result is `allMatch: true`, exit 0. Its fixed evidence file is preserved if present.
The local wasm-bindgen output remains an input to that comparison, not an authenticated external
reference. Neither static helper proves that malicious code is absent, identifies who made a
change, authenticates the operating system/toolchain, or establishes a pre-incident baseline.
The review conclusions and limitations are local evidence in
`docs/audits/AUD-018-evidence/browser-malicious-review.json`.
