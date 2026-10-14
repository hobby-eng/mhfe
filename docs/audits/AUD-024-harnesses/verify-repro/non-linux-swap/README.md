# AUD-024 verify-repro: the swap warning of a non-Linux build

Harness of audit AUD-024, written for commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`. It checks
what a Windows or macOS build of the `mhfe` tool says about swap before any secret is typed.

`non_linux_swap.py` copies, unchanged, `unprotected_swap` from `src/bin/mhfe/protect/swap.rs`, the
`SwapArea` and `SwapInventory` types from `src/bin/mhfe/protect.rs` and `swap_warning` from
`src/bin/mhfe/settings.rs` into one Rust file. It replaces `cfg!(target_os = "linux")` with `false`,
the value that macro has in a build for Windows or macOS, and stubs `style::escaped`, which only
escapes a name. It compiles that file with `rustc`, runs it, and prints a control line (an
`Unavailable` inventory warns) and the inventory and warning of the non-Linux build.

Inputs: the three source files above, read from the repository root; a scratch folder for the
generated `.rs` file and its binary. Needs Python 3 and the pinned `rustc` of
`rust-toolchain.toml`. No Argon2, no network, no secret.

Command, from the repository root:

```sh
python3 docs/audits/AUD-024-harnesses/verify-repro/non-linux-swap/non_linux_swap.py <scratch>
```

Expected output at b6fca69 (exit 1, the defect is there):

```text
control (Unavailable): Some("MHFE cannot read the Linux swap inventory, so its encryption is unknown.")
non-Linux build: inventory Available([]), warning None
FAIL: a non-Linux build reports an inspected, empty swap inventory and warns nothing
```

Exit 0 (`PASS: ...`) once a non-Linux build warns or reports its swap as unknown; exit 2 when the
sources no longer have the shape the harness extracts, which a fix that moves the platform test may
cause: then check the fix with its own unit tests instead.
