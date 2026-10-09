# Statistical control witnesses

These bounded audit-only calculations belong to AUD-014. They replay a retained analytic model of the baseline controls, not the current production implementation or a mutated production test suite. The baseline had HEAD `abb16671b641378c0fc3c4d855f8d126498e754b` and uncommitted changes. The script pins its original five word-index cases, original threshold formula, fixed-word positions and exact original source hashes; the audit report's manifest identifies the complete reviewed tree. It requires only Python's standard library and performs no wallet derivation, Argon2, build, network request or source mutation.

Baseline source identities:

- `src/word_wishes/statistics.rs`: SHA-256 `c37e51afba891e1c7ae3f46e484e3e159357a2ef70aa52879b41cf84e655d23e`.
- `src/word_wishes/known_answers.rs`: SHA-256 `9c06ddfd6ef638ace96da6d5854a4158dbdace45fa7fa89b3ef5ea60ce433079`.

Run from the MHFE repository root:

```sh
python3 docs/audits/AUD-014-harnesses/tests/statistical-controls.py
```

The script independently calculates three baseline witnesses from its pinned constants:

- Swapping two middle bits leaves every existing five-value isolation fixture unchanged, while changing 1,024 of the 2,048 possible word values. A fault confined to position 2 also avoids the independently expected fixed-word startup cases and the fixed-position statistical draw cases.
- The position chi-square threshold's upper-tail probability differs materially from the stated approximate value of one in a million. The regularized upper incomplete gamma calculation checks two integer-shape cases against their closed forms and the 23-degree case against an independent half-integer recurrence starting from the complementary error function.
- Uniform conditioning on an anywhere word and forcibly inserting it at a random position have different duplicate probabilities. Counting only singleton placements and non-chosen-word marginals does not test this difference.

Exit zero means these bounded mathematical witnesses succeeded; any failure exits nonzero. JSON is printed to standard output. If the local-only initial command log `docs/audits/AUD-014-evidence/baseline-stat-controls.log` exists, the script also checks that its captured source identities and mathematical results agree. That file is optional and is not changed. The initial command evidence remains the record of inspection before remediation; this replay works after the source assertions have been strengthened and does not claim they still contain the baseline controls.

The bit-exchange witness is an integer model of a possible setter fault, not evidence that a production-suite mutant was executed. The current Rust unit tests separately use checksum-valid poison samples to prove that positional bias, copied bits and forced anywhere insertion are rejected. This analytic replay does not establish production entropy or treat the checksum word as mathematically independent of its entropy.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: ca0086acf545d07bfe008ae340554124a48442bf -> abb16671b641378c0fc3c4d855f8d126498e754b.
