# AUD-024 verify-platform-hardening harness

A static trace for audit AUD-024, written for commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`.
It checks one finding: the Windows release build locks no secret memory and takes no step
against crash dumps or same-user memory reading, and the macOS build does not deny debugger
attachment, although each system has an equivalent (coding guide RUST-09 and RUST-13).

What it does, reading files only:

1. Prints `rustc --print cfg` for the release targets `x86_64-pc-windows-gnu`,
   `x86_64-apple-darwin` and `aarch64-apple-darwin`, which shows which `cfg` branches each
   target compiles. It needs `rustc` of the pinned toolchain on `PATH`, and only prints the
   cfg if `rustc` is missing.
2. Prints the branches the Windows and macOS builds compile: `lock_pages`, `unlock_pages` and
   `page_size` off Unix (`src/engine/ffi.rs`), the `memory-locking` check off Unix
   (`src/memory.rs`), the whole body of `harden_process` and the core-dumps reason off Unix
   (`src/bin/mhfe/protect.rs`), and the `windows-sys` features (`Cargo.toml`).
3. Searches `src/**/*.rs`, `Cargo.toml`, `build.rs`, `scripts/*.sh` and
   `.github/workflows/*.yml` for each platform equivalent: `VirtualLock`; a Windows Error
   Reporting exclusion (`WerRegisterExcludedMemoryBlock`, `WerAddExcludedApplication` or
   `WerSetFlags`); a process DACL (`SetSecurityInfo` or `SetKernelObjectSecurity`); and on
   macOS `PT_DENY_ATTACH` or a hardened-runtime signature (`codesign ... --options runtime`).

Inputs: the repository tree at the commit under test. No secret and no test data.

Command, from the repository root, on Linux with Python 3:

```sh
python3 docs/audits/AUD-024-harnesses/verify-platform-hardening/platform_hardening.py
```

Expected at b6fca69: the cfg lines `target_os="windows" windows` and `target_os="macos" unix`;
the non-Unix `lock_pages` returning `false`; the check's `NotAvailable("this build locks no
memory on this system")`; `harden_process` with only a `#[cfg(unix)]` `setrlimit` block and a
`#[cfg(target_os = "linux")]` `prctl` block; four `MISSING` lines; then `FAIL: 4 platform
equivalent(s) of RUST-09/RUST-13 missing in the Windows or macOS build`, exit 1.

A fix passes it (exit 0) once each equivalent is present. The search proves only that the call
exists, not that it works. A fix still needs the Windows and macOS CI runs that read each
protection back (RUST-11).

## Remediation trace

The trace accepts both `pub fn` and `pub(crate) fn` for the startup entry. It also recognizes
process-local `SetErrorMode(... SEM_NOGPFAULTERRORBOX)`: Microsoft's
[SetErrorMode contract](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode)
says this bypasses normal WER invocation. `WerSetFlags` alone is insufficient evidence: its
`WER_FAULT_REPORTING_NO_UI` flag only suppresses UI. The implementation reads its process flag
back with `GetErrorMode`; it does not edit a user's or machine's WER registry policy.

This is a static presence trace. Passing it or Windows cross-compilation does not establish
native enforcement, dump contents or release reproducibility; the platform tests and artifact
checks named in AUD-024 remain separate evidence.
