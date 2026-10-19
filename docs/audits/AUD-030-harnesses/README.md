# AUD-030 command evidence

This harness belongs to the current-tree MHFE audit based on commit
`575cbd1b7634646f6e19a2501ed9ea164a6a7acd` plus its pre-existing uncommitted changes.
The report's baseline source manifest identifies those changes; the commit alone does not.
No checkout is copied and no production setting or cryptographic parameter is changed.

Run from the existing MHFE repository with its pinned Node and Rust toolchains and the workspace
`CARGO_HOME` and `RUSTUP_HOME` environment variables:

```sh
node docs/audits/AUD-030-harnesses/record-command.mjs baseline-fast bash scripts/check-fast.sh
```

Use a unique evidence name for every invocation. The Linux-only recorder writes a command log
and JSON receipt to ignored `docs/audits/AUD-030-evidence/`, retaining command arguments,
selected nonsecret environment variables, UTC times, exit status, log hash, and the exact
non-audit source maps before and after execution. Exit zero means the command exited zero
without a recorder error or resource stop; it is not a whole-repository acceptance verdict.

Only public fixtures and synthetic inputs are permitted. Do not pass secrets in arguments.
One heavy command may run at a time. The recorder limits its descendant processes to a sampled
2 GiB RSS budget, retains at least 3 GiB available machine memory, limits Node heaps to 768 MiB,
sets one Cargo/test/Emscripten worker, and stops after 30 minutes. Shared pages can be counted
more than once, and one-second samples can miss short peaks. These limits do not reduce
production Argon2 costs or authorize full-size campaigns. Existing artifact outputs and
native-platform acceptance must be assessed separately.
