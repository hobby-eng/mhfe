# verify-cargo-pin-gate (AUD-024, commit b6fca69)

Adversarial verification of the candidate finding that the CORE-25 check of `Cargo.toml` in
`scripts/verify-code-rules.mjs` (`cargoFindings`, lines 255-273) reads only `name = …` lines at the
start of a line under a section header that ends in `dependencies`.

## cargo-pin-gate-e2e.sh

What it checks: the repository's own gate script, copied unchanged with
`scripts/gate-command-line.mjs` into a throwaway git repository (made with `mktemp -d`, removed on
exit), is run without arguments once for each crafted `Cargo.toml`. Every manifest except the
second control declares a dependency whose requirement is not `=x.y.z`; Cargo reads each of them
as a dependency (`cargo metadata --no-deps` gives requirements `^1.2`, `*`, `^1`, `>=1`).

Inputs: `scripts/verify-code-rules.mjs` and `scripts/gate-command-line.mjs` of the working tree,
and the manifests written in the script. Needs `node` and `git`; no network, no build.

Command, from the repository root:

```
docs/audits/AUD-024-harnesses/verify-cargo-pin-gate/cargo-pin-gate-e2e.sh
```

Expected output at b6fca69 (exit code 1): the two controls are decided right (`gate exit 1` for
`foo = "1.2"`, `gate exit 0` for `foo = "=1.2.3"`), the nine other manifests give `gate exit 0`
with "The repository keeps the coding guide's rules that code-rules checks.", and the last line is
`FAIL: 9 manifests decided wrong; Cargo reads each as a dependency (see README.md)`.

After a fix the gate refuses all nine, and the last line is
`PASS: the gate refuses every manifest with a dependency not pinned as "=x.y.z"` (exit code 0).
