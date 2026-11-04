# Security

MHFE is experimental research software and has not been reviewed by independent cryptographers.
Passing tests and matching vectors do not establish that the construction is secure. The [specification](https://github.com/hobby-eng/mhfe-spec) states its
protocol assumptions and limits.

Report suspected vulnerabilities privately through
[GitHub's security advisory form](https://github.com/hobby-eng/mhfe/security/advisories/new).
Never include a real seed phrase, password, private key or wallet file.

## Secrets

### Terminal input and output

The tool accepts secrets through terminal prompts or standard input (`--stdin`), never as command
arguments. It does not write secret files or logs, and its error messages contain no part of a
phrase or password. Redirecting output, supplying input through another program, terminal logging
and screen recording can still retain secrets outside MHFE.

An interactive prompt uses the terminal's alternate screen when available. It shows typed text so
mistakes can be seen, then clears the screen and returns to the main screen. New containers and
recovered phrases use the same private screen until Enter or Escape. It keeps those lines out of
the main scrollback; anyone watching or recording the screen can read them meanwhile.

Without an alternate screen, such as with `TERM=dumb`, secret input has no echo, container input
remains visible and requested output stays on the main screen. Features that would expose an extra
phrase require a private screen on the output terminal: `new` refuses to start, `decrypt` offers
one password, and `rekey` omits the owner's visual confirmation when that screen is unavailable.
Redirected output or output to another terminal does not qualify.

Password input preserves characters for validation rather than silently removing controls.
Backspace, Ctrl+U, Enter, Ctrl+D on an empty line and Ctrl+C have their editing or cancellation
meaning. Word input also supports Tab completion and Ctrl+W; in a password those keys reach
validation and are refused as controls. Control bytes are never echoed as terminal commands.
Unread input left by a paste is discarded when the prompt or list ends, so it cannot answer the
next question or reach the shell.

Terminal settings and the private screen are restored on handled cancellation. SIGTERM and a
closed terminal stop the tool like Ctrl+C; Ctrl+\\ and Ctrl+Z do so outside a prompt or list. At a
prompt they are characters for validation. The terminal suite covers input and restoration in a
pseudo-terminal on Linux and macOS and a pseudo-console on Windows. The menu also restores the
terminal after a command crashes or is killed; a standalone process killed without cleanup cannot
do that itself. See [terminal controls](docs/CLI.md#terminal-input-and-cancellation).

### Memory ownership and wiping

Owned secret buffers are wiped when dropped: phrases, passwords, passphrases, entropy, state, keys,
masks and private scalars. The tool reads and writes secret text through operating-system calls,
bypassing standard-library input/output buffers that would retain it. A standard-input answer is
limited to 8,192 bytes and read one byte at a time into a fixed-size locked buffer; it neither
reads ahead nor reallocates the answer.

Longer-lived secret buffers use mhfe-core's `Secret`, reserved at a fixed size, locked before data
is written and unlocked after wiping. This covers typed and generated passwords, passphrases and
their normalized forms, phrase text, recovered readings, terminal frames and scrollable results,
BIP39 seeds, BIP32 keys, entropy, and the cipher's states and round material. Each buffer owns its
pages. Locking is best effort, and a warning reports refusal.

On Linux x86-64 and AArch64, `memfd_secret` is used where available. Its pages cannot be read
directly through `/proc/PID/mem`, `process_vm_readv` or `PTRACE_PEEKDATA`, including by root.
Fallback storage uses `mlock` on Linux and macOS or `VirtualLock` on Windows; Windows secret
buffers are also excluded from error reports. No memory is locked in a browser.

Short-lived copies are wiped but not locked: words being parsed or expanded, entropy and seeds
first returned by BIP39, temporary hashes, curve scalars, random bytes and word indexes. Buffers
inside dependencies and copies made by the compiler in registers or on the stack are outside the
buffer owners' control. mhfe-core overwrites 128 KiB of stack after secret computations, including
each of its four Argon2 threads after a call. The native engine wipes its work area on success and
failure. These measures cannot guarantee removal of every copy made by a dependency, compiler,
operating system or terminal.

Ctrl+C ends work immediately, including during a long round. The operating system reclaims process
memory; the handler does not first wipe every buffer. A high PIM can make a round take hours, so
cancellation does not wait for it to finish.

### Swap and hibernation

The Argon2 work area is locked only when the system's locked-memory limit can hold it. Linux's
usual 8 MiB limit cannot hold the default 2 GiB. Stored Argon2 blocks can make password guesses
cheap to test, so protecting just the typed password is insufficient.

On Linux, a command handling secrets tries to forbid swap before reading them. With disk-backed
swap it restarts in a systemd user scope with `MemorySwapMax=0` and reads that limit back. This
requires a systemd user session and covers the process's stack, heap and work area. If it cannot
forbid swap, dm-crypt swap, directly or under LVM, is accepted; other or unidentified swap requires
confirmation, and a command without a terminal stops. Zram without disk writeback stays in memory.
With swap forbidden, insufficient RAM can cause the system to kill the process.

macOS encrypts swap. Windows offers no per-process way to forbid its page file: MHFE tries to lock
the work area and asks whether to continue if that fails. BitLocker or disabling the page file is
needed to cover the remaining memory. A browser page cannot enforce any of these controls.

Hibernation can write locked memory and the work area to disk. Linux refuses hibernation while
kernel secret memory exists; elsewhere an encrypted disk is needed. Avoiding disk copies matters
because TRIM and overwriting do not guarantee that an SSD forgets them.

### Random phrases

MHFE makes no randomness of its own. A new phrase's 256 bits, every trial of a draw for the phrase +
passphrase check and every generated password come straight from the operating system's
cryptographic generator, through the `getrandom` crate; the `bip39` crate of the rust-bitcoin
project turns the bits into words. A source that gives nothing or repeats itself is refused before
it is used. At every start MHFE checks its word lists, keys and addresses against values computed
with independent implementations, among them
[@scure/bip39](https://github.com/paulmillr/scure-bip39), audited by Cure53, and the other audited
@scure and @noble libraries that the multi-chain wallet tools use. No test can show that a
generator is unpredictable; these checks find one that is stuck or plainly broken.

### Output and confirmation rules

The [README](README.md#menu) describes the commands. Their shared security rules are:

- A new container is returned to another program only after its creation check passes. An
  interactive preview is marked unchecked until then; failure or cancellation invalidates that
  preview. This checks the operation performed, not every possible hardware fault.
- A rekey holds recovered state in locked memory and seals it only after `Rekey::confirm` accepts
  the confirmation. A unique built-in check at the stated shorter length can suffice; detection,
  conflicting lengths and unchecked formats need a wallet reference or, where permitted, the
  owner's comparison with an independent backup. The 16-bit wallet check alone never confirms it.
- Multi-password decryption keeps extra passwords, settings, progress and results on one private
  screen and out of the summary, including on handled cancellation. Scrollable lines are held in
  buffers that MHFE attempts to lock and wipes when the screen closes. The largest requested
  Argon2 allocation is attempted before results appear; on failure it may use the first password's
  level and privately skip recoveries needing more memory. No option records the extra-password
  count. The process keeps temporary session material, but writes no record of it.
- Password check-word repairs show password words only on a private terminal screen and require
  a person's choice. A fitting check word neither identifies the container's password nor adds
  password strength. Its word indexes are wiped.

## Process isolation

Every command except `serve` enters mhfe-core's isolation before reading input, including
`self-test` and `test-benchmark`. It cannot be undone, applies to threads the command starts, and
reads back each protection. A warning names one that did not take effect. The menu holds no secret
and stays outside isolation so it can launch commands and the browser server separately.

### Linux

Core dumps are disabled with `RLIMIT_CORE=0`; `PR_SET_DUMPABLE=0` prevents ordinary same-user
programs attaching or reading process memory. A command stops before its first question if core
dumps remain enabled.

On x86-64 and little-endian AArch64, seccomp refuses socket creation, io_uring, filesystem-changing
calls, `ptrace`, `process_vm_writev`, `pidfd_getfd` and non-terminal `ioctl`s. Landlock refuses
file writes, creation, removal and renaming from Linux 5.13, and TCP bind/connect from Linux 6.7;
on other architectures it is the available filesystem restriction. A private network namespace
with inactive loopback is used where user namespaces are allowed.

### macOS

Core dumps are disabled with `RLIMIT_CORE=0`. `PT_DENY_ATTACH` refuses debuggers unless the process
is already traced. A sandbox refuses network access and file writes except to the terminal and
`/dev/null`.

### Windows

Process and thread access lists restrict same-user memory access. Low integrity refuses writes to
the user's normal files and registry, but leaves low-integrity folders and filesystems without
access control, such as FAT and exFAT, writable. Network access stays open because closing it
requires administrator rights; the command warns.

Secret buffers and the Argon2 work area are excluded from Windows error reports, and isolation
omits the heap. Reports may still contain thread stacks and registers; the self-test reports this
limit. A same-user program may also duplicate a handle held by the parent shell or menu and use
it to reach the command.

### Limits

These restrictions do not contain an administrator, root, `CAP_SYS_PTRACE` or a debugger the tool
was started under, apart from the direct secret-memory reads described above. They do not revoke
inherited descriptors: an existing socket, writable file, pipe or redirected output stays usable.
Start MHFE from a trusted terminal in an offline environment.

The browser package loads no remote resources and contains no network loaders; the build removes
unused loaders emitted by Emscripten and wasm-bindgen. The two fast-mode launchers below are the
exceptions to the tool's lack of network use. They listen locally and receive no secrets.

## The Argon2 engines and unsafe code

Native builds use RustCrypto's `argon2` through mhfe-core, which also owns memory protection and
process isolation. Its [security notes](https://github.com/hobby-eng/mhfe_core/blob/523f9e48a9dd2c84581e44f7f8636627dd496209/SECURITY.md)
describe the engine's cleanup and platform limits. Browser builds use the unchanged
[reference C implementation](vendor/phc-winner-argon2.md), compiled with Emscripten. MHFE's separate
`src/engine/argon2_browser.c` clears the stack used by that reference code.

The library denies unsafe Rust except for the free-memory queries in `src/engine/ffi.rs` on
macOS and Windows. The command-line tool allows it in three operating-system adapters:

| Module                         | Calls it owns                                                                            |
| ------------------------------ | ---------------------------------------------------------------------------------------- |
| `src/bin/mhfe/protect.rs`      | Signal routing, terminating a menu child, reading locked-memory limits                   |
| `src/bin/mhfe/raw_io.rs`       | Unbuffered Unix input and Windows console input                                          |
| `src/bin/mhfe/hidden_input.rs` | Terminal modes, width, key availability, restoration and identifying the output terminal |

## Containers of the same length

Suite 4 is offered only as an explicit choice after its consequences are shown. It has no built-in
check, exposes the original word count and catches fewer copying errors than a 24-word container.
Its smaller state is outside the specification's suite 3 attack-cost estimates. Every recovered
phrase is marked unverified and needs a wallet comparison. Both the original seed phrase and
container are valid BIP39 phrases of the same length; only the owner's records distinguish them.
See the [format table](README.md#24-words-or-the-same-length) and
[protocol explanation](docs/HOW-IT-WORKS.md#the-container).

## The fast-mode launcher

`mhfe serve` and the browser package's `core/mhfe-fast-mode.py` serve one HTML file with the headers
needed for threaded Argon2. The Python launcher needs Python 3.8 or later and its standard library.
Their threat model includes other local programs and web pages trying to contact them.

- They listen on a random port at `127.0.0.1` and accept only `GET` and `HEAD` for `/`.
- An exact `Host: 127.0.0.1:<port>` is required; another site's DNS-rebinding request is refused
  with 403.
- Responses set Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy,
  `Content-Security-Policy: frame-ancestors 'none'`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- At most 16 connections run at once, each with a total 10-second request deadline and a separate
  10-second response deadline.
- They read no request body, keep no log, list no directory and serve no other file. The page
  performs the secret operations in the browser; neither launcher receives them.
- The adjacent `mhfe-fast-mode.sha256` must name the page and match its SHA-256. This detects
  accidental damage or replacement, not tampering by someone able to change both files. Verify
  the release's checksums and signature too.

`cargo xtask fast-mode` tests both launchers on the same cases and compares their headers and
limits. A secret entered in a standard-mode tab is not passed to the fast-mode tab.

## The browser

The [browser package](docs/BROWSER-PACKAGE.md) shares the Rust library and provides independent
classes for core operations, repair, passwords and wallet tools. It cannot provide native memory
locking, swap controls, private terminal screens, crash-report controls or process isolation.

### Workers and lifetime

A worker handles each operation and is terminated when it ends, releasing Argon2 memory. It keeps
the page responsive and supports cancellation; it is not a trust boundary because it shares the
page's origin and browser process. Cancellation, failed callbacks, package mismatches, failed
worker-message delivery and failed Argon2 rounds can free memory without overwriting it.

Longer-lived workers retain more material. A hidden-wallet session keeps its Argon2 area, main
passphrase and used passwords until `close()`; an idle close wipes them, while a close during work
terminates the worker. Rekey confirmations and a check's `onNoLength` answer retain recovered state
until the page answers. A new-phrase draw runs sequential trials in one worker until completion.

### Copies in the page

After startup checks and argument validation, the class copies secret input to UTF-8 bytes and
transfers that copy to its worker. A caller's `Uint8Array` is copied, not emptied. Unpaired
surrogates are refused. Worker-owned input, keys and states are wiped where the Rust and Argon2
code can reach them; secret result buffers are wiped after conversion to JavaScript strings.

JavaScript strings cannot be wiped by the page. This includes typed passwords and phrases,
generated passwords, recovered phrases, check-word repairs and owner-confirmation text. Prefer
`Uint8Array` for input passwords and passphrases, remove displayed secrets when done and close the
tab. The [host requirements](docs/BROWSER-PACKAGE.md#what-the-page-should-do) describe concealment,
confirmation and session cleanup.

### Checks and package identity

Each class checks known answers before use and offers slower checks on request. Argon2 operations
also check their build before and after their rounds. A failed component closes the class. These
checks can detect wrong computation, but cannot establish unpredictable randomness or the native
protections absent from a page. Only the requested full-size `selfTest()` covers Argon2 at 2 GiB.

Every package file carries a build identifier. `PACKAGE_MISMATCH` refuses files mixed from
different builds. An attacker able to edit a file can edit its identifier too; release checksums,
their OpenPGP signature and build attestations serve a different purpose and must be verified.
