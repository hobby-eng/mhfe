# Security

MHFE is experimental research software. It has not been reviewed by independent cryptographers; do
not use it to protect real funds. A passing test or a matching vector does not show that the
construction is secure. The protocol and its limits are described in the
[specification](https://github.com/hobby-eng/mhfe-spec).

Report a suspected vulnerability privately through GitHub's security advisories for this repository.
Never include a real seed phrase, password, private key or wallet file.

## Secrets

- Secrets are typed at a terminal or read from standard input with `--stdin`. At a terminal they
  are typed on a private screen, the terminal's alternate screen, which shows them as they are
  typed so that a slip can be seen, and which is cleared and left as soon as they are accepted, or
  on Ctrl+C; neither the secret nor the result reaches the main screen or its scrollback. A new
  container and a recovered seed phrase are shown the same way, until the person presses Enter or
  Escape after writing them down, and a container typed for a recovery or a check is read on a
  private screen as well. Anyone who can see the screen meanwhile can read them. Where no private
  screen is possible, they are typed without echo. A phrase that the person did not ask to export
  is shown only on a private screen: `new` and `wallets` refuse to start, and `rekey` does not
  offer the owner's comparison, when standard output is not a terminal that has one, such as when
  it goes to a file, a pipe or another terminal than the one the private screen is shown on. The
  tool never takes secrets from command-line arguments, never writes them to files and never logs
  them. Error messages never contain a phrase, a password or any part of them.
- A secret's prompt reads the line exactly as typed or pasted. Only Backspace, Ctrl+U, Enter, Ctrl+D
  on an empty line and Ctrl+C keep their meaning; every other character, including those a
  terminal would usually act on (Ctrl+S, Ctrl+Q, Ctrl+V, Ctrl+W, Ctrl+Z, Ctrl+\\), reaches the
  password check, which refuses a control character instead of removing it; a control character
  is never written back to the terminal, which would act on it. The terminal settings are restored
  after the answer and on Ctrl+C. `scripts/verify-hidden-input.py` checks this
  in a pseudo-terminal on Linux and macOS, and `scripts/verify-hidden-input-windows.py` in a
  Windows pseudo-console; CI runs them on all three systems.
- Every buffer the program owns that holds a password, phrase, passphrase, entropy, state, Argon2
  key or mask is wiped when it is dropped; short-lived working buffers inside dependencies, such as
  those of Unicode normalization and BIP39 word parsing, are not. The Argon2 work area is wiped by
  the C code at the end of every round (`FLAG_clear_internal_memory`, checked by a test); when a
  round fails, for example because a thread could not be started, the C code returns before that
  step and the Rust owner wipes the area instead. This is best effort: a compiler, the operating
  system, swap or a terminal's scrollback can keep copies beyond the program's reach, and so can the
  standard library's own buffer of standard input. Answers read from standard input are limited to
  8192 bytes and read into a buffer of that size, so the program's copy never has to grow and leave
  an unwiped copy behind. At a terminal, secrets, a new container and a recovered phrase appear on
  the terminal's alternate screen, which is cleared before the tool returns to the main screen, so
  they do not enter its scrollback; a terminal that logs its output or a screen recording keeps
  them all the same.
- The tool keeps secrets out of core dumps and swap. It forbids core dumps (`RLIMIT_CORE` 0) and,
  on Linux, makes itself non-dumpable (`PR_SET_DUMPABLE` 0), which also keeps other programs of the
  same user from attaching to it or reading its memory through `/proc`, so a crash writes nothing
  to disk; the Argon2 work area is marked `MADV_DONTDUMP` as well. The password, the original
  phrase while it is encrypted, the entropy kept for the check, a recovered phrase, a BIP39
  passphrase and the line a secret is typed into are locked in memory (`mlock`), so that the system
  does not write them to swap; a typed line stays locked until it is wiped. The system locks whole
  pages, and one page may hold several secrets, so the tool counts the secrets on each page and
  unlocks it only after the last of them is wiped. This is best effort and does not apply in a
  browser or on Windows.
  The Argon2 work area, gigabytes in size, cannot be locked, and from its blocks a password guess
  can be tested cheaply. On Linux the tool therefore warns, before any secret is typed, when a swap
  area is not encrypted with dm-crypt, directly or under LVM, or when it cannot tell; swap in memory
  (zram) is safe. macOS encrypts its swap; on Windows, use BitLocker or no page file.
- `encrypt` asks for the password twice, also with `--stdin`, and then decrypts the new container
  again from its words and compares the result with the original phrase: a typing mistake or a
  hardware fault cannot silently produce a container that no password opens. At a terminal the
  container is shown during that check, marked as not yet verified, and the outcome is reported;
  a failed or cancelled check says that the container must not be relied on. With `--stdin`, or
  when standard output goes to a file or another program, the container is printed only after
  the check has passed.
- `rekey` recovers the phrase into locked memory. It encrypts it again only once the recovery is
  confirmed (`Mhfe::recover_confirmed`): by the built-in check at the length the owner states, by
  an address or the fingerprint of the wallet, or by the owner, who chose to see the phrase on a
  private screen and compare it with their backup. So a wrong password cannot be sealed into a new
  container that then looks verified. It does not revoke the old container, and says so.
- `new` draws a new phrase from the operating system's random generator, on every processor core
  when it must pass a check with the BIP39 passphrase, and shows it only on a private screen. That
  check is a draft over the BIP39 seed with the passphrase, which may not be empty: a filter of 16 bits that a
  wrong password or passphrase passes once in about 65,536. It never shows which wallet it is, and
  `rekey` does not accept it as the only confirmation.
- `wallets` shows hidden wallets all on one private screen with their passwords and progress, so
  that the main screen shows neither the wallets nor how many were opened, and it keeps no record
  of the passwords or the wallets.
- A password from `mhfe password --check-word` has a sixth word computed from the other five
  (MHFE-PASSWORD-CHECK-1). When six list words are typed, the program may offer to restore or
  replace one of them before any Argon2 work. The offer shows words of the password, so it is made
  only on the private screen and only to a person at a terminal; nothing is changed unless they
  choose it, and the summary says only how the check word came out. The list positions it computes
  are wiped. The check word adds no strength and is as secret as the rest of the password.
- Nothing connects to a network. The browser package loads no remote resources and contains no
  network code: the build replaces the unused file loaders that Emscripten and wasm-bindgen emit
  (`scripts/remove-network-code.mjs`), and the only network code in the tool is `mhfe serve`, which
  listens on 127.0.0.1 for the one page it serves and never receives a secret (see below).
- On Linux the kernel enforces this. A command that handles secrets (`encrypt`, `decrypt`, `check`,
  `rekey`, `new`, `wallets`, `password`) runs under a seccomp filter that refuses to create any
  socket, and refuses io_uring altogether, whose operations could create one without the system
  call the filter sees; and under a Landlock ruleset that refuses every write to the file system
  (Linux 5.13 and later; from Linux 6.7 also TCP bind and connect). Both cover every thread the
  command starts, Argon2's included, and cannot be undone; the start menu runs each command in a
  thread of its own, so that it can still start `mhfe serve`, which is not isolated because the
  browser it opens must write its profile. The summary of a command says what the kernel enforces.
  A fault or a tampered dependency therefore cannot send a secret away or leave it in a file; the
  program's own output goes only to the terminal or to where standard output is redirected.
- Ctrl+C ends the tool at once, also inside a round. The operating system then discards all of its
  memory; buffers are not wiped first, because a round can take hours at a high PIM.

## The C engine and its boundary

Argon2 is the reference C implementation, vendored unchanged (see
[`vendor/phc-winner-argon2.md`](vendor/phc-winner-argon2.md)). All unsafe Rust code of the library
is in one module, `src/engine/ffi.rs`; the rest of the library denies it (`#![deny(unsafe_code)]`).
The engine module also makes the calls that lock secrets in memory and keep the work area out of
core dumps (`mlock`, `madvise`). The command-line tool denies unsafe code too, except in
`src/bin/mhfe/protect.rs`, which forbids core dumps (`setrlimit`, `prctl`) and isolates a command
(seccomp, Landlock), and in
`src/bin/mhfe/hidden_input.rs`, which switches the
terminal's echo and line mode for a secret's prompt and a list (`tcgetattr`/`tcsetattr` on Unix,
`GetConsoleMode`/`SetConsoleMode` on Windows) and restores them, and reads the terminal's width and
whether a key follows Escape (`ioctl`/`select` on Unix, `GetConsoleScreenBufferInfo`/
`PeekConsoleInputW` on Windows). The engine module keeps these
invariants:

- `argon2_context` is copied field for field; compile-time assertions check its size, alignment and
  every field offset on 32- and 64-bit targets, and a test proves that every field reaches the C
  code, including `flags` and the callbacks.
- Every pointer handed to C refers to a live Rust buffer of the stated length that outlives the
  call, or is NULL with length 0. Inputs are shared borrows that C only reads: MHFE never sets the
  flags that would make C write to the password or secret. The output and the work area are
  exclusive borrows.
- On x86-64, `opt.c` is compiled twice, with SSE2 and with SSSE3. MHFE's own
  `src/engine/argon2_simd.c` runs the SSSE3 copy only for a call whose context carries MHFE's flag
  in bit 31 of `flags`, which the engine sets only where the processor reports SSSE3; the vendored
  code reads only the two lowest bits. The choice travels with each call, so no global state is
  shared.
- The work area is allocated once per operation and handed to C by the allocation callback. The C
  API passes no user data to the callback, so the area travels in a thread-local slot that is set
  just before and cleared just after each call; C calls the callback on the calling thread.
- `argon2_ctx` joins its four lane threads before it returns and keeps no other global state, so no
  pointer outlives a call and calls on different threads do not interfere.
- Every Argon2 error code is turned into an error with the reference implementation's message.

The only other unsafe calls in that module are the free-memory queries for macOS and Windows.

## Containers of the same length

A container of the same length as its 12- to 21-word original (suite 4, `--same-length`, or
`sameLength` in the browser) is made only when the user chooses it; 24 words are the default, and
the tool and the documented page behaviour show the consequences before the choice. Compared with a
24-word container:

- It has no built-in check. A wrong password, PIM or memory level gives another valid phrase of the
  same length with no error, so only a comparison with the wallet (`mhfe check --address` or
  `--fingerprint`) confirms a recovery, and every recovered phrase is labelled as not verified.
- It shows the original's word count, and its BIP39 checksum of 4 to 7 bits lets a miscopied word
  through about once in 16 to 128, against once in 256 for 24 words.
- Its state is the entropy itself, 128 to 224 bits in two halves of 64 to 112 bits, so each round's
  salt is drawn from at most 2^64 to 2^112 values. The specification extends its analysis of
  plausible deniability to this state, but does not assert its suite 3 conjectures on attack cost
  for it; treat the format as newer and less analysed than the 24-word one.
- A container is told apart from its original only by the user's own records: both are valid phrases
  of the same length, and a wallet accepts either.

## The fast-mode launcher

`mhfe serve` serves one HTML file so that the browser allows the threaded Argon2 build. The browser
package's `mhfe-fast-mode.py` is the same launcher for computers with Python but without mhfe; it
uses only the Python standard library, keeps every rule below, and
`scripts/verify-fast-mode-script.py` tests it on the same cases as `mhfe serve`, including its
security headers. Their threat model: other programs and web pages on the same computer may try to
talk to them.

- Each listens on 127.0.0.1 only, on a random port, and answers only `GET` and `HEAD` of `/`.
- It refuses any request whose `Host` header is not exactly `127.0.0.1:<port>`. A web page on
  another site whose name was made to resolve to 127.0.0.1 (DNS rebinding) sends its own name as the
  host and is refused with 403.
- It sends `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`,
  `Content-Security-Policy: frame-ancestors 'none'`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control: no-store`.
- Each connection is answered in its own thread, at most 16 at a time, and has 10 seconds in
  total for its request and 10 seconds in total for receiving the answer, so a slow or stalled
  client cannot keep the page from loading.
- It reads no request body, keeps no log, serves no other file and lists no directory. It never
  receives a secret: the page does all the work in the browser.
- It serves a page only when the checksum file `mhfe-fast-mode.sha256` next to it names that page
  with a matching SHA-256, and otherwise refuses with a message and serves nothing. This catches a
  damaged, swapped or partly updated page. It does not replace checking the release: someone who
  can change the page can change the checksum file next to it too, so compare the release files
  with the published `SHA256SUMS` once, after downloading.

A secret typed into a page in standard mode stays in that tab; it is never passed to the fast-mode
tab.

## The browser

- The package fetches nothing and needs no `connect-src`; it works under a policy that allows
  scripts only by hash, WebAssembly and `blob:` workers.
- Each operation runs in its own worker, which is terminated afterwards; that frees the Argon2
  memory. The worker is a boundary for responsiveness and cancellation, not a vault. If an Argon2
  round fails in the browser, the C code leaves its work area unwiped, and the worker's memory is
  discarded with the worker rather than overwritten.
- The Rust core and the Argon2 bridge wipe their copies of the password, keys and states. A password
  typed into a page is a JavaScript string, and so is a recovered phrase shown on the page; browsers
  cannot erase strings. The client refuses a password with an unpaired surrogate instead of letting
  the browser replace it silently. It checks every setting before it copies a secret into bytes and
  wipes its copies if the operation cannot start; the core takes both the password and the BIP39
  passphrase into wiping buffers before anything can fail.
