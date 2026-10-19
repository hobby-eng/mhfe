# AUD-027 acceptance harnesses

These scripts belong to the scoped AUD-027 acceptance follow-up, reviewed against base commit `575cbd1b7634646f6e19a2501ed9ea164a6a7acd` plus the report's uncommitted source manifest. The base commit alone does not identify that working tree.

`canonical-receipt.py` compares every member of the reviewed 17-file browser package with `dist/` and the four required Windows licence texts with their source files. It refuses missing, altered, duplicated or unsafe entries and bounds archive/text inspection. It does not execute binaries, establish native platform behavior or prove reproducibility. Its literal catalog records this audit's package; it is not a catalog for future releases.

Use Python 3.11 or later and run from the MHFE repository root. First build the standard browser package with `scripts/build-wasm.sh` and the canonical archives with the procedure in `docs/RELEASING.md`. Supply the canonical output's `release/` directory:

```sh
python3 docs/audits/AUD-027-harnesses/canonical-receipt.py canonical-output/release
python3 docs/audits/AUD-027-harnesses/receipt-controls.py ../tmp/mhfe-receipt-controls
python3 -O docs/audits/AUD-027-harnesses/receipt-controls.py ../tmp/mhfe-receipt-controls
```

The receipt command prints JSON containing archive hashes, 17 browser payload hashes, four matching licence hashes and the Windows build information. Success exits 0; any mismatch exits nonzero. The controls print two positive archive checks and eight expected refusals, and fail if the wrong refusal occurs or an invalid archive is accepted. They create only disposable public archive fixtures under the supplied scratch directory and remove them after the run. Neither script changes a source file or `dist/`.

Command logs, source manifests and original failures are local-only evidence under `docs/audits/AUD-027-evidence/`. The report states their hashes and explains interrupted checks; these harnesses do not turn an interrupted run into a successful complete run.
