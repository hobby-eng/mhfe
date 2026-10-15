# AUD-025 CORE review witnesses

These scripts belong to the scoped CORE conformance review of the dirty MHFE tree based on
`968424528984235635f187551126b2925d705297`, non-audit source fingerprint
`12c7f4fb5b4ad9ba4cb7e20a9eee0c97922125128781f7a8a57b6c1e366e45f6`.
The working tree, rather than HEAD alone, identifies the reviewed code.

The baseline commands in this section run from the existing MHFE repository with Node 26.10.0
and Git. They need no extra dependency, wallet input, network request, cryptographic workload or
second project checkout. The dated browser smoke below has its own prerequisites.

```sh
node docs/audits/AUD-025-harnesses/core-review.mjs --self-test
node docs/audits/AUD-025-harnesses/core-review.mjs --inventory
node docs/audits/AUD-025-harnesses/core-review.mjs --check
```

`--self-test` must exit 0 after its positive and negative controls. `--inventory` exits 0 and
lists production Rust public free-function/field candidates with source lines; it is an inventory,
not an assertion that each candidate is a defect. The inherited lexical reader and macros limit
what the inventory establishes; source contracts and field visibility still require review.

`--check` is a conformance probe: it exits 1 on the reviewed snapshot because representative
public writable records, the remaining free check-word calculation, and the internal Argon2
startup error without a code property are present. It exits 0 only after those witnesses are
absent. The probe evaluates only the actual standalone error-class definition; it never starts
the worker, initializes Argon2, handles a secret or runs an old audit's workload. It is bounded
evidence for the cited conformance gaps, not proof of complete CORE compliance or a runtime
security vulnerability.


## Dated remediation smoke

`browser-remediation-smoke.mjs` belongs to the 2026-10-15 remediation addendum, not the discovery
baseline. Run after `scripts/build-wasm.sh`, with the repository's pinned Playwright and its
installed Chromium/Firefox. It uses the existing checkout and public fixtures only:

```sh
node docs/audits/AUD-025-harnesses/browser-remediation-smoke.mjs
```

It launches the browsers one at a time, opens a generated ignored file under `target/aud025-smoke/`
with the package's offline CSP, and exercises actual Blob workers: module startup (including the
standard Argon2 startup known answer, not full-cost MHFE), metadata,
phrase normalization, independently known fingerprint, published check-word vector, overlong
refusal and readonly error. It prints per-browser JSON/timing and exits 0 on success. Each page
has a 120-second deadline and its browser is closed in `finally`. No encryption, random wallet
drawing, full-cost vector or real wallet material is used. Observed startup times do not prove
a universal timing bound. This is standard-mode smoke, not the full browser/launcher matrix.

The addendum binds final uncommitted source and package hashes. The baseline core-review probe
now exits 0 on the fixed source; its original failing reproduction and discovery identity above
remain historical evidence.

## Implementation commit binding — 2026-10-15 (UTC)

The current remediation source is recorded in SSH-signed implementation commit
`12f12032cca2215d11237e4e717690a1ccd75f29`, source fingerprint `9d485ddc61c3edfe51a864160a712e96945f7cf8108d00f1728fcd4ec384e403` (454 non-audit files).
This identity supplements the historical discovery/continuation snapshots above. The retained
checks were performed before committing on those exact source bytes; committing did not rerun
them. The associated report preserves the remaining platform and release acceptance limits.
