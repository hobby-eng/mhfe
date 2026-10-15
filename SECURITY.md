# Security

MHFE is experimental research software. It has not been reviewed by independent cryptographers; do
not use it to protect real funds. A passing test or a matching vector does not show that the
construction is secure. The protocol and its limits are described in the
[specification](https://github.com/hobby-eng/mhfe-spec).

Report a suspected vulnerability privately through GitHub's security advisories for this repository.
Never include a real seed phrase, password, private key or wallet file.

## Secrets

- Secrets are typed interactively at a terminal or read from standard input with `--stdin`.
  Where a private screen is available, they are typed on the terminal's alternate screen, which shows them as they are
  typed so that a slip can be seen, and which is cleared and left as soon as they are accepted, or
  on Ctrl+C; neither a secret displayed there nor its result reaches the main screen or its scrollback. A new
  container and a recovered seed phrase are shown the same way, until the person presses Enter or
  Escape after writing them down, and a container typed for a recovery or a check is read on a
  private screen as well. Anyone who can see the screen meanwhile can read them. Where no private
  screen is possible, secrets are typed without echo. `password`, `encrypt`, `decrypt` and `rekey`
  refuse interactive result display before input or work; explicit redirection still exports the
  result. `--stdin` uses the script protocol and exports to standard output without a private-screen
  guarantee. A phrase that the person did not ask to export
  is shown only on a private screen: `new` and `wallets` refuse to start, and `rekey` does not
  offer the owner's comparison, when standard output is not a terminal that has one, such as when
  it goes to a file, a pipe or another terminal than the one the private screen is shown on. The
  tool never takes secrets from command-line arguments, opens no file to store them and never logs
  them; a caller can explicitly redirect its standard output. Error messages never contain a phrase,
  a password or any part of them.
- A secret's prompt reads the line exactly as typed or pasted. Only Backspace, Ctrl+U, Enter, Ctrl+D
  on an empty line and Ctrl+C keep their meaning. A line of words, such as a seed phrase, a
  container phrase or a chosen word, is no password, so there Tab also completes the word being
  typed as far as the words of its list agree, and Ctrl+W deletes the last word. Every other
  character, including those a terminal would usually act on (Ctrl+S, Ctrl+Q, Ctrl+V, Ctrl+Z,
  Ctrl+\\, and Ctrl+W in a password), reaches the password check, which refuses a control character
  instead of removing it; a control character is never written back to the terminal, which would
  act on it. The terminal settings are restored after the answer and on Ctrl+C. SIGTERM and a
  closed terminal end the tool as Ctrl+C does, and so do Ctrl+\\ and Ctrl+Z outside such a prompt
  or a list, so that none leaves a private screen with a secret on it.
  `scripts/verify-hidden-input.py` checks this in a pseudo-terminal on Linux and macOS, and
  `scripts/verify-hidden-input-windows.py` in a Windows pseudo-console; CI runs them on all three
  systems.
- Every buffer the program owns that holds a password, phrase, passphrase, entropy, state, Argon2
  key or mask is wiped when it is dropped, and so are the SHA-256, SHA-512, HMAC and BLAKE2b states
  fed with them (their crates' `zeroize` features); short-lived working buffers inside other
  dependencies, such as those of Unicode normalization, BIP39 word parsing and the PBKDF2 of the
  BIP39 seed, are not. The Argon2 work area is wiped by the C code at the end of every round
  (`FLAG_clear_internal_memory`, checked by a test); when a round fails, for example because a
  thread could not be started, the C code returns before that step and the Rust owner wipes the area
  instead. This is best effort: a compiler, the operating system, swap or a terminal's scrollback
  can keep copies beyond the program's reach, and so can the standard library's line buffer of
  standard output, which keeps the last line a phrase or a container was printed on until later
  output overwrites it. Standard input bypasses the standard library's persistent buffer: Unix
  descriptors and Windows pipes read one byte at a time, and the Windows console reads one Unicode
  scalar with `ReadConsoleW`. Pending UTF-8 bytes are held in an owned buffer, locked where the
  system permits, and wiped when consumed or dropped. Answers are limited to 8192 bytes and read into a buffer
  of that size, so the program's copy never has to grow and leave an unwiped copy behind. At a
  terminal, secrets, a new container and a recovered phrase appear on the terminal's alternate
  screen, which is cleared before the tool returns to the main screen, so they do not enter its
  scrollback; a terminal that logs its output or a screen recording keeps them all the same.
- The CLI requests native crash-dump and memory-access protections. It forbids Unix core dumps
  (`RLIMIT_CORE` 0) and,
  on Linux, makes itself non-dumpable (`PR_SET_DUMPABLE` 0), which also keeps other programs of the
  same user from attaching to it or reading its memory through `/proc`, so a crash writes nothing
  to disk; the Argon2 work area is marked `MADV_DONTDUMP` as well. Windows opts the process out of
  Windows Error Reporting with `SEM_NOGPFAULTERRORBOX`, read back through `GetErrorMode`, and sets
  a restrictive process DACL. An `OWNER RIGHTS` ACE also removes the owner's implicit ability to
  grant itself memory-read access; the exact DACL is read back before secret input. macOS requests
  `PT_DENY_ATTACH`; release binaries are ad-hoc signed with the hardened runtime and no debugger
  entitlement. `csops` reads that running policy back; local builds without a verified runtime
  report that limitation. These measures cannot stop an administrator, a privileged debugger,
  a handle obtained before hardening, or a host that controls the program itself.
  The secrets the program keeps beyond a moment are held in locked memory (`mlock` on Unix,
  `VirtualLock` on Windows), so that the system does not write them to
  swap: the line a secret is typed into at a terminal or read from standard input; the password as
  Argon2 receives it; a BIP39 passphrase and its normalized form; a password made by the generator
  or completed by its check word; a seed phrase as text, whether typed, recovered, new or a hidden
  wallet's, and every reading of a recovery that `check` compares with an address or a
  fingerprint; and a phrase's entropy and the cipher's state, that is the state an encryption
  starts from until its check is done, both halves of the state through all twelve rounds, the
  message of each round that holds one of them, and the state a recovery, a check, a rekey or a
  hidden wallet recovers. Each of these buffers is reserved at a size it never outgrows, locked
  before anything is written into it, and unlocked only after it is wiped, also when what is
  written into it is refused, such as a password that is too long. Copies made on the way are
  wiped when dropped but not locked: the words of a typed phrase while they are read and written
  out in full, the entropy as the BIP39 library first gives it, the hash that fills out a short
  phrase's state while it is computed, the random bytes and word numbers a phrase or password is
  drawn from, the BIP39 seed for an address, a fingerprint or the wallet check and the keys derived
  from it, each round's Argon2 key, salt and mask, the lines of the frame a phrase is shown in at a
  terminal, and buffers inside dependencies. The system locks whole pages, and one page may hold
  several secrets, so the tool counts the secrets on each page and unlocks it only after the last
  of them is wiped. This is best effort on native Linux, macOS and Windows builds; Windows may
  increase its small working-set allowance when the existing quota refuses a lock, with a 64 MiB
  ceiling for that allowance. A browser locks nothing.
  The Argon2 work area, gigabytes in size, cannot be locked, and from its blocks a password guess
  can be tested cheaply. On Linux the tool therefore warns, before any secret is typed, when a swap
  area is not encrypted with dm-crypt, directly or under LVM, or when it cannot tell, as for a
  device whose entry in /sys it cannot see; swap in memory (zram) is safe only without a writeback
  device, or with one encrypted as above. macOS encrypts its swap; on Windows, use BitLocker or no
  page file. MHFE does not inspect Windows pagefile encryption, so it warns that protection is
  unknown rather than reporting a protected or absent pagefile.
- `encrypt` asks for the password twice, also with `--stdin`, and then decrypts the new container
  again from its words and compares the result with the original seed phrase: a typing mistake or a
  hardware fault cannot silently produce a container that no password opens. At a terminal the
  container is shown during that check, marked as not yet verified, and the outcome is reported;
  a failed or cancelled check says that the container must not be relied on. With `--stdin`, or
  when standard output goes to a file or another program, the container is printed only after
  the check has passed.
- `rekey` recovers the phrase into locked memory (`Rekey::recover_state`) and encrypts it again
  only once the recovery is confirmed (`Rekey::confirm`, the guard in `src/rekey.rs` that the tool
  and the browser package both go through). The built-in check confirms it only at a 12- to
  21-word length the owner states, when the check passes at that length and at no other. With the
  length detected, for a 24-word original seed phrase or a same-length container, which have no
  check, and when the check finds another length than the one stated (`LENGTH_DIFFERS`) or several
  lengths pass, only an address or the fingerprint of the wallet confirms it, or the owner, who
  chose to see the phrase on a private screen and compare it with their backup. Where the owner
  could not tell the phrase from another reading, as with 24 words stated beside a shorter length
  whose check passes, only the address or the fingerprint confirms it. So a wrong password cannot
  be sealed into a new container that then looks verified. It does not revoke the old container,
  and says so.
- `new` draws a new phrase from the operating system's random generator, on every processor core
  when it must pass a check with the BIP39 passphrase, and shows it only on a private screen. That
  check is a draft over the BIP39 seed with the passphrase, which may not be empty: a filter of 16
  bits that a wrong password or passphrase passes once in about 65,536. It never shows which wallet
  it is, and `rekey` does not accept it as the only confirmation.
- `wallets` shows hidden wallets all on one private screen with their passwords and progress, so
  that the main screen shows neither the wallets nor how many were opened, and it keeps no record
  of the passwords or the wallets.
- A password from `mhfe password --check-word` has a sixth word computed from the other five
  (MHFE-PASSWORD-CHECK-1). When six list words are typed, the program may offer to restore or
  replace one of them before any Argon2 work. The offer shows words of the password, so it is made
  only on the private screen and only to a person at a terminal; nothing is changed unless they
  choose it, and the summary says only how the check word came out. The list positions it computes
  are wiped. The check word adds no strength and is as secret as the rest of the password.
- The browser JavaScript loads no remote resources. The build removes the unused Emscripten and
  wasm-bindgen file loaders (`scripts/remove-network-code.mjs`); a shared lexical gate checks
  known network and dynamic-code constructs, with two counted Worker exceptions. The gate is a
  tripwire for those constructs, not a proof about arbitrary code. The native `mhfe serve` and
  the browser package's Python launcher listen on 127.0.0.1 for the one page they serve and never
  receive a secret (see below).
- On Linux the kernel enforces this. A command that handles secrets (`encrypt`, `decrypt`, `check`,
  `rekey`, `new`, `wallets`, `repair`, `repair-words`, `password`) runs under a seccomp filter that
  refuses to create any socket, and refuses io_uring altogether, whose operations could create one
  without the system call the filter sees; under a Landlock ruleset that refuses every write to the
  file system (Linux 5.13 and later; from Linux 6.7 also TCP bind and connect); and under a second
  seccomp filter that refuses what Landlock leaves of a write: changing a file's mode, owner,
  extended attributes or times, and truncating it by path, which Landlock refuses only from Linux
  6.2. "No new file writes" is stated only when both hold. All of them cover every thread the
  command starts, Argon2's included, and cannot be undone. A command started directly also moves
  into a network namespace of its own, with only inactive loopback and no external routes; where the
  system allows no user namespaces it runs on without one. Its summary says "isolated network, no
  new sockets or file writes" with the namespace and "no new sockets or file writes" without it. The
  start menu runs each command in a thread of its own, so that it can still start `mhfe serve`,
  which is not isolated because the browser it opens must write its profile; a thread cannot get a
  namespace of its own, so the menu's commands have the filter and the ruleset only. The summary of
  a command says what the kernel enforces. These restrictions do not revoke descriptors already open:
  an inherited socket remains in its original network namespace, and an already writable file, pipe
  or redirected standard output remains writable. They therefore restrict new access rather than
  guarantee containment of arbitrary compromised code. Start the tool from a trusted terminal in the
  offline environment described above. `serve` remains outside these command restrictions so that a
  browser can reach its localhost listener.
- Ctrl+C ends the tool at once, also inside a round. The operating system then discards all of its
  memory; buffers are not wiped first, because a round can take hours at a high PIM.

## The C engine and its interface

Argon2 is the reference C implementation, vendored unchanged (see
[`vendor/phc-winner-argon2.md`](vendor/phc-winner-argon2.md)). The library denies unsafe Rust except
in the small native-call modules: `src/engine/ffi.rs` owns the C engine and work-area dump
exclusion, and `src/memory/os.rs` with `memory/os/windows.rs` owns page locking. The command-line
tool denies unsafe code too, except in
`src/bin/mhfe/protect.rs` with its modules `protect/seccomp.rs` and `protect/landlock.rs`, which
forbids core dumps (`setrlimit`, `prctl`), routes Ctrl+\\ and Ctrl+Z to the Ctrl+C handler
(`sigaction`, `raise`), isolates a command (seccomp through `prctl`, Landlock, a network namespace
through `unshare`), and reads each protection back by asking for it or trying what it forbids
(`getrlimit`, `prctl`, `socket`, io_uring, `open`); its `protect/windows.rs` owns the Windows
error-mode and process-DACL calls, and `protect/macos.rs` owns `ptrace` and `csops`. Raw input calls
live in `standard_input.rs` and `standard_input/windows.rs`. The terminal modules of
`src/bin/mhfe/hidden_input.rs`, `hidden_input/unix.rs` and `hidden_input/windows.rs`, which switch
the terminal's echo and line mode for a secret's prompt and a list (`tcgetattr`/`tcsetattr` on
Unix, `GetConsoleMode`/`SetConsoleMode` on Windows, where they also have the console carry out
control sequences) and restore them, read the terminal's width and whether a key follows Escape
(`ioctl`/`select` on Unix, `GetConsoleScreenBufferInfo`/`PeekConsoleInputW` on Windows), and tell
whether standard output is the terminal the private screen is shown on (`fstat` on Unix,
`GetConsoleMode` on Windows). The engine module keeps these invariants:

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

A container of the same length as its 12- to 21-word original seed phrase (suite 4, `--same-length`,
or `sameLength` in the browser) is made only when the user chooses it; 24 words are the default, and
the tool and the documented page behaviour show the consequences before the choice. Compared with a
24-word container:

- It has no built-in check. A wrong password, PIM or memory level gives another valid phrase of the
  same length with no error, so only a comparison with the wallet (`mhfe check --address` or
  `--fingerprint`) confirms a recovery, and every recovered phrase is labelled as not verified.
- It shows the original seed phrase's word count, and its BIP39 checksum of 4 to 7 bits lets a
  miscopied word through about once in 16 to 128, against once in 256 for 24 words.
- Its state is the entropy itself, 128 to 224 bits in two halves of 64 to 112 bits, so each round's
  salt is drawn from at most 2^64 to 2^112 values. The specification extends its analysis of
  plausible deniability to this state. Its suite 3 guessing bounds, proved in the random-oracle
  model for the specified single-container or single known-pair games, do not extend to suite 4; treat
  the format as newer and less analysed than the 24-word one.
- A container is told apart from its original seed phrase only by the user's own records: both are
  valid phrases of the same length, and a wallet accepts either.

## The fast-mode launcher

`mhfe serve` serves one HTML file so that the browser allows the threaded Argon2 build. The browser
package's `mhfe-fast-mode.py` is the same launcher for computers with Python but without mhfe; it
uses only the Python standard library, keeps every rule below, and
`scripts/verify-fast-mode-script.py` tests it on the same cases as `mhfe serve`, including its
security headers; the request heads and checksum files that both must decide alike are one list,
`tests/fixtures/fast-mode-cases.json`, which the tests of both read. Their threat model: other
programs and web pages on the same computer may try to talk to them.

Both serve only a file whose name ends in lower-case `.html`; this suffix rule is case-sensitive.
Other names have their own refusal, even when the checksum line is well formed.

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
  with a matching SHA-256, and otherwise refuses with a message and serves nothing. Both must be
  regular files, the checksum file at most 4 KiB and the page at most 64 MiB, and nothing beyond
  that is read of them. This catches a damaged, swapped or partly updated page. It does not replace
  checking the release: someone who can change the page can change the checksum file next to it too,
  so compare the release files with the published `SHA256SUMS` once, after downloading.

A secret typed into a page in standard mode stays in that tab; it is never passed to the fast-mode
tab.

## The browser

The browser package ([`docs/BROWSER-PACKAGE.md`](docs/BROWSER-PACKAGE.md)) runs the same Rust code
and the same Argon2 C code in a web page, as independent classes: `MhfeClient` (encryption,
recovery, the check, rekey, hidden wallets, the search for missing words of a container phrase and
the self-test), `MhfeRepair`, `MhfePasswords` and `MhfeWallet`. A page has none of the
protections of the operating system described above: no private screen, no locked memory, no
control of crash reports and no isolation of its own.

- The package fetches nothing and needs no `connect-src`; it works under a policy that allows
  scripts only by hash, WebAssembly and `blob:` workers. The page passes its files to each class
  as text and bytes.
- Every operation runs in a worker of its own, which is terminated when the operation ends; that
  frees the Argon2 memory. The worker provides responsiveness and cancellation, not a
  vault: it runs in the page's browser process and origin. A cancelled operation is stopped at
  once, and its memory is freed without being overwritten; so is the work area of an Argon2 round
  that fails, which the C code leaves unwiped in the browser.
- A page callback that fails, or whose answer is refused, also ends its worker without guaranteeing
  the Rust session's own wipe (`CALLBACK_FAILED`, or the returned `TypeError` or `MhfeError`).
  So do `PACKAGE_MISMATCH`, an unexpected worker message and `WORKER_FAILED`, including a failed
  send. Normal worker completions attempt their explicit cleanup; termination alone promises no
  overwrite.
- Some work holds secrets in workers for longer. A session of hidden wallets keeps its
  worker with its Argon2 work area, the main wallet's BIP39 passphrase and the passwords used so
  far, which it needs to refuse a password used twice, until the page closes it; `close()`
  overwrites them before the worker ends, and a close while a wallet opens stops the worker at
  once instead. A new phrase with the wallet check is drawn in several workers at once, by
  default as many as the processor has cores, at most eight, or as many as the page asks for, each
  from the browser's random generator (`crypto.getRandomValues`), and every worker ends with the
  draw.
- A rekey waiting for the owner or `onConfirmAgain` keeps its old and new passwords and recovered
  state; a check waiting for `onNoLength` keeps its recovered state. The wait lasts as long as the
  page takes to answer. Cancel the operation when the user leaves or stops using it.
- A password, a BIP39 passphrase, a phrase and dice rolls given to a class are copied into UTF-8
  bytes only after the class's check at start has passed and every setting is checked. The copies
  are transferred to the worker, so that none stays with the class, and are wiped when the operation
  cannot start; a `Uint8Array` the page passes is copied, not emptied. Text with an unpaired
  surrogate is refused instead of being silently changed by the browser. In the worker, the Rust
  code takes these bytes into buffers that it wipes, and it wipes its own copies of the keys and
  states; a result that holds a secret is written into a buffer of its final size, which is wiped
  once the result has become a JavaScript string. Copies that the compiler and the dependencies
  leave on the WebAssembly's stack, such as the BIP39 seed and the BIP32 master key of a fingerprint
  or a wallet check and the passphrase in BIP39's PBKDF2 salt block, are zeroed by the worker after
  every operation and before every question to the page, when no WebAssembly code runs
  (AUD-024-SEC003); Argon2's C code clears the stack each lane leaves after every segment, natively
  and in both browser builds (AUD-024-SEC002). A browser locks no memory. An operation in which the
  WebAssembly stops (a trap) ends with `INTERNAL_ERROR` and its worker is terminated without its
  session being wiped.
- What the page holds as a JavaScript string cannot be wiped, since browsers cannot erase strings:
  a password or phrase typed into the page, a recovered or new phrase, the phrase shown to the
  owner to confirm a rekey, the phrases of hidden wallets, a generated password and the words of a
  check word review, `readPhrase()`'s written-out words and the secret-derived strings returned by
  `wordHints()`. Pass passwords and passphrases as `Uint8Array` where possible, keep such
  values on screen only as long as needed and close the tab afterwards.
- The rules of the library hold in the browser too: a rekey seals only a recovery that is confirmed,
  the wallet check of a new phrase needs a BIP39 passphrase and never confirms a rekey, and a hidden
  wallet's password is refused when it was used already or when its wallet would pass a check. What
  the terminal's private screen does falls to the page: `docs/BROWSER-PACKAGE.md` ("What the page
  should do") asks it to show the phrase of an owner's confirmation concealed and remove it after
  the answer, to remove a recovered phrase from the screen once the user is done, to show no list or
  count of the hidden wallets opened, and to close a session of hidden wallets when the user leaves
  the page and after a while without use.
- Every class checks its parts with known answers and public test data before its first operation
  (`startupCheck()`), and on request with slower cases (`fullCheck()`); every Argon2 operation
  checks its Argon2 build before its first round and after its last. A wrong answer closes the
  class for good, so that a page that checks its classes when it opens shows the fault before
  anything secret is typed. These checks find a broken build, a damaged file that changes an answer
  and a browser that computes wrongly. They cannot check locked memory, crash reports, isolation or
  a random generator that is deterministic but looks random, and only `selfTest()`, which takes
  minutes, covers Argon2 at its full 2 GiB.
- Every file a page loads carries a build identifier derived from all of them, and files of
  different builds are refused with `PACKAGE_MISMATCH`. This catches files mixed by accident, not
  deliberate tampering: whoever can change a file can change its identifier too. Check the package
  against the release's `SHA256SUMS` and its OpenPGP signature for that.
