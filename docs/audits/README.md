# MHFE audit records

These files record reviews of the experimental MHFE implementation. They are
evidence reports, not cryptographic proofs or independent security
certifications.

| Audit | Date | Reviewed snapshot | Result |
| ----- | ---- | ----------------- | ------ |
| [AUD-001](audit-01-2026-09-22.md) | 2026-09-22 | Uncommitted prototype, source fingerprint `7952ef4c…415a` | Seven implementation and documentation findings remediated; significant cryptographic and cross-browser limitations remain |
| [AUD-002](audit-02-2026-09-22.md) | 2026-09-22 | Commit `12b26a33`, source fingerprint `7fee380e…c0236` | Conformance confirmed (published replay, three independent differential vectors, Node.js WASM round trip); three low findings open (Worker/WASM PIM integer wrap, no runtime check of browser exports and stale local build, private vulnerability reporting disabled and specification unlinked) |

Machine-readable companions are
[`audit-01-2026-09-22.json`](audit-01-2026-09-22.json) and
[`audit-02-2026-09-22.json`](audit-02-2026-09-22.json).
