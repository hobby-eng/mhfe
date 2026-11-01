# Security

MHFE is experimental research software. It has not been reviewed by independent cryptographers; do
not use it to protect real funds. A passing test or a matching vector does not show that the
construction is secure. The protocol and its limits are described in the
[specification](https://github.com/hobby-eng/mhfe-spec).

Report a suspected vulnerability privately through
[GitHub's security advisory form](https://github.com/hobby-eng/mhfe/security/advisories/new).
Never include a real seed phrase, password, private key or wallet file.

## Secrets

- Secrets are typed at a terminal or read from standard input with `--stdin`. At a terminal they
  are typed on a private screen, the terminal's alternate screen, which shows them as they are
  typed so that a slip can be seen, and which is cleared and left as soon as they are accepted, or
  on Ctrl+C; neither the secret nor the result reaches the main screen or its scrollback. A new
  container and a recovered seed phrase are shown the same way, until the person presses Enter or
  Escape after writing them down, and a container typed for a recovery or a check is read on a
  private screen as well. Anyone who can see the screen meanwhile can read them. Where no private
  screen is possible, such as with `TERM=dumb`, secrets are typed without echo, a container is shown
  as it is typed, and a result goes to the main screen and stays in its scrollback. A phrase that the person did not ask to export
  is shown only on a private screen: `new` and `wallets` refuse to start, and `rekey` does not
  offer the owner's comparison, when standard output is not a terminal that has one, such as when
  it goes to a file, a pipe or another terminal than the one the private screen is shown on. The
  tool never takes secrets from command-line arguments, never writes them to files and never logs
  them. Error messages never contain a phrase, a password or any part of them.
- A secret's prompt reads the line exactly as typed or pasted. Only Backspace, Ctrl+U, Enter, Ctrl+D
  on an empty line and Ctrl+C keep their meaning. A line of words, such as a seed phrase or a
  container phrase, is no password, so there Tab also completes the word being
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
  key or mask is wiped when it is dropped; what a dependency keeps on the stack is not, such as the
  parsing states of the `bip39` crate. mhfe-core therefore overwrites 128 KiB of the stack after
  each call that computes with a secret, and each of the four threads of its Argon2 engine does
  the same after every call of that engine, which also wipes the Argon2 work area, whether the
  call succeeded or not. This is best effort: a compiler, the operating system, swap or a terminal's
  scrollback can keep copies beyond the program's reach. Standard input and standard output are
  read and written with the operating system's own calls (`read` and `write`, and the console's
  UTF-16 calls on Windows), past the standard library's buffers, which are never wiped and would
  keep the last answer read ahead or the last phrase printed; `clippy.toml` keeps `io::stdin`,
  `io::stdout` and `println!` out of every other module. Answers read from standard input are
  limited to 8192 bytes and read one byte at a time into a locked buffer of that size, so nothing
  after an answer is taken and the program's copy never has to grow and leave an unwiped copy
  behind. What was typed at the terminal and not read when a hidden prompt or a list ends is
  discarded, so the rest of a paste never reaches the next answer or the shell. At a terminal,
  secrets, a new container and a recovered phrase appear on the terminal's alternate screen, which
  is cleared before the tool returns to the main screen, so they do not enter its scrollback; a
  terminal that logs its output or a screen recording keeps them all the same.
- A crash of a command writes no secret to disk, as far as the system allows. Every command but
  `serve` enters mhfe-core's isolation (`Isolation::enter`) before it reads anything and keeps what
  reads back as holding. On Linux and macOS it forbids core dumps (`RLIMIT_CORE` 0). On Linux it
  also makes itself non-dumpable (`PR_SET_DUMPABLE` 0), which keeps other programs of the same user
  from attaching to it or reading its memory through `/proc`, and on macOS it refuses debuggers
  (`PT_DENY_ATTACH`), unless one already traces it. A command whose core dumps stay on stops before
  its first question. Windows has no such setting: secrets and the Argon2 work area are left out of
  its error reports, and isolation leaves out the heap, but a report still holds the threads'
  stacks and registers; `mhfe self-test` says so, and a command goes on. The start menu and `serve`
  hold no secret and enter no isolation, so neither forbids core dumps or makes itself
  non-dumpable: the menu reads only keys and the kind of a password.
- The secrets the program keeps beyond a moment are held in locked memory, so that the system does
  not write them to swap: the line a secret is typed into at a terminal or read from standard
  input; the password as Argon2 receives it; a BIP39 passphrase and its normalized form; a password
  made by the generator or completed by its check word; a seed phrase as text, whether typed,
  recovered, new or a hidden wallet's, every reading of a recovery that `check` compares with an
  address or a fingerprint, and the lines of the frame a phrase is shown in at a terminal; the
  BIP39 seed for an address, a fingerprint or the wallet check and the BIP32 keys derived from it;
  and a phrase's entropy and the cipher's state, that is the state an encryption starts from until
  its check is done, both halves of the state through all twelve rounds, the message, salt, Argon2
  key and mask of each round, and the state a recovery, a check, a rekey or a hidden wallet
  recovers. Each of these buffers is a `Secret` of mhfe-core, reserved at a size it never outgrows,
  locked before anything is written into it, and unlocked only after it is wiped, also when what is
  written into it is refused, such as a password that is too long. The system locks whole pages, so
  each of these buffers has pages of its own. On Linux on x86-64 and AArch64 they are the kernel's
  secret memory (`memfd_secret`) where it is offered, which no other process, root included, reads
  directly through `/proc/PID/mem`, `process_vm_readv` or `PTRACE_PEEKDATA`. Otherwise `mlock` holds
  them on Linux and macOS; on Windows `VirtualLock` does, and they are left out of error reports.
  Copies made on the way are wiped when dropped but not locked: the words of a typed
  phrase while they are read and written out in full, the entropy and the BIP39 seed as the BIP39
  library first gives them, the hashes that fill out a short phrase's state, make a round's salt
  and mask or give a BIP32 key while they are computed, a BIP32 key as a scalar while the curve uses
  it, the random bytes and word numbers a phrase or password is drawn from, and buffers inside
  dependencies. Locking is best effort, natively on Linux, macOS and Windows; nothing is locked in a
  browser.
- The Argon2 work area, gigabytes in size, is locked only where the limit on locked memory holds
  all of it, which on Linux it usually does not (8 MiB by default), and from its blocks a password
  guess can be tested cheaply. On Linux a command that reads secrets therefore forbids itself swap
  before it reads anything: where swap lies on a disk, encrypted or not, it starts itself again in
  a systemd scope with `MemorySwapMax=0`, so that no page of it, stack, heap and work area included,
  can reach swap, and reads the limit back. That needs a user session of systemd. Where it cannot
  be done, swap encrypted with dm-crypt, directly or under LVM, is accepted, as only ciphertext
  reaches the disk. Any other swap, and swap the tool cannot tell of, is named, and the person is
  asked whether to go on; without a terminal the command stops. Swap in memory (zram) that writes
  back to no disk is safe. With swap forbidden and too little memory, the system ends the process
  rather than write to a disk. macOS encrypts its swap; on Windows, no program can forbid its page
  file: a command locks the work area and asks whether to go on where Windows refuses, and only
  BitLocker or no page file covers the rest of its memory. A browser page has no such means at all. What never
  reaches a disk needs no erasing: TRIM and overwriting do not guarantee that an SSD forgets.
  Hibernation writes locked memory and the work area to disk: on Linux the kernel refuses to
  hibernate while secret memory exists, and elsewhere only an encrypted disk protects them.
- `encrypt` asks for the password twice, also with `--stdin`, and then decrypts the new container
  again from its words and compares the result with the original seed phrase: a typing mistake or a
  hardware fault that does not repeat cannot silently produce a container that no password opens. At a terminal the
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
- `new` draws a new phrase from the operating system's random generator, on one thread, one trial
  after another, when it must pass a check with the BIP39 passphrase, and shows it only on a private
  screen. That check is a draft over the BIP39 seed with the passphrase, which may not be empty: a
  filter of 16 bits that a wrong password or passphrase passes once in about 65,536. It never shows
  which wallet it is, and `rekey` does not accept it as the only confirmation.
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
  (`cargo xtask wasm remove-network-code`), and the only network code in the tool is `mhfe serve`
  and the optional launcher `mhfe-fast-mode.py`, which listen on 127.0.0.1 for the one page they
  serve and never receive a secret (see below).
- The operating system enforces as much of this as it offers. Every command but `serve` enters
  isolation before it reads anything: `encrypt`, `decrypt`, `check`, `rekey`, `new`, `wallets`,
  `repair`, `repair-words`, `password`, `self-test` and `test-benchmark`. It cannot be undone and
  covers every thread the command starts, Argon2's included. Each protection is read back, and the
  summary of a command says what holds and warns when the network stays open or other programs
  can read the memory.
- On Linux on x86-64 and little-endian AArch64, a seccomp filter refuses to create any socket, and
  refuses io_uring altogether, whose operations could create one without the system call the filter
  sees. It also refuses every call that changes the file system, `ptrace`, `process_vm_writev`,
  `pidfd_getfd` and every `ioctl` but the terminal's. A Landlock ruleset refuses writing, creating,
  removing and renaming files (Linux 5.13 and later; from Linux 6.7 also TCP bind and connect), and
  on other architectures it is all that applies. A command also moves into a network namespace of
  its own, with only inactive loopback and no external routes; where the system allows no user
  namespaces it runs on without one. Its summary says "isolated network, no new sockets or file
  writes" with the namespace and "no new sockets or file writes" without it.
- On macOS a sandbox refuses network access and file writes, except for the terminal and
  `/dev/null`, and the summary says "no network or file writes".
- On Windows the access lists of the process and its threads keep programs of the same user from
  opening them to read or change them, and a command runs at low integrity, which refuses writes to
  the user's files and registry. Low-integrity folders and volumes without access control, such as
  FAT and exFAT USB sticks and SD cards, stay writable, so the summary says "low integrity, most
  file writes refused". Sockets stay open, since only an administrator can close them, and the
  summary warns of that. A program of the same user can still duplicate the handle that whatever
  started the command holds, the start menu or a shell, and reach the command through it.
- Root, a program with `CAP_SYS_PTRACE`, an administrator and a debugger the tool was started under
  are not kept out, apart from the secret memory above. These boundaries do not revoke descriptors
  already open either: an inherited socket remains in its original network namespace, and an
  already writable file, pipe or redirected standard output remains writable. They therefore
  restrict new access rather than guarantee containment of arbitrary compromised code. Start the
  tool from a trusted terminal in the offline environment described above. `serve` remains outside
  these command restrictions so that a browser can reach its localhost listener.
- The start menu runs each command as a process of its own on the same terminal, isolated as a
  typed command is and with its own checks at start. The menu itself stays out of isolation, so
  that it can still start `mhfe serve`, which is not isolated because the browser it opens must
  write its profile. A command that crashed or was killed could not restore the terminal or leave
  its private screen, so the menu does both and says so.
- Ctrl+C ends the tool at once, also inside a round. The operating system then discards all of its
  memory; buffers are not wiped first, because a round can take hours at a high PIM.

## The Argon2 engines and their boundary

Natively, Argon2 is RustCrypto's `argon2` crate inside mhfe-core, which also makes the calls
that lock secrets, isolate a process and keep the work area out of core dumps. The
[security notes of mhfe-core](https://github.com/hobby-eng/mhfe_core/blob/v0.2.0/SECURITY.md)
give what its engine leaves and clears and what each system offers and leaves open. The browser
package compiles the reference C implementation from
[`vendor/phc-winner-argon2`](vendor/phc-winner-argon2.md) with Emscripten, with one C file of
MHFE's own, `src/engine/argon2_browser.c`, which clears the stack behind the reference code.

The only unsafe Rust code of the library is in `src/engine/ffi.rs`, the free-memory queries for
macOS and Windows; the rest of the library denies it (`#![deny(unsafe_code)]`). The command-line
tool denies unsafe code too, except in three modules:

- `src/bin/mhfe/protect.rs` routes Ctrl+\\ and Ctrl+Z to the Ctrl+C handler (`sigaction`, `raise`),
  passes a request to end on to a command of the start menu (`kill`) and reads the limit on locked
  memory (`getrlimit`);
- `src/bin/mhfe/raw_io.rs` reads standard input with the operating system's calls (`read` on Unix,
  `ReadConsoleW` on a Windows console);
- `src/bin/mhfe/hidden_input.rs` switches the terminal's echo and line mode for a secret's prompt
  and a list (`tcgetattr`/`tcsetattr` on Unix, `GetConsoleMode`/`SetConsoleMode` on Windows, where
  it also has the console carry out control sequences) and restores them, reads the terminal's
  width and whether a key follows Escape (`ioctl`/`select` on Unix,
  `GetConsoleScreenBufferInfo`/`PeekConsoleInputW` on Windows), and tells whether standard output
  is the terminal the private screen is shown on (`fstat` on Unix, `GetConsoleMode` on Windows).

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
  plausible deniability to this state, but does not assert its suite 3 conjectures on attack cost
  for it; treat the format as newer and less analysed than the 24-word one.
- A container is told apart from its original seed phrase only by the user's own records: both are
  valid phrases of the same length, and a wallet accepts either.

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

The browser package ([`docs/BROWSER-PACKAGE.md`](docs/BROWSER-PACKAGE.md)) runs the same Rust code
and the reference Argon2 C code in a web page, as independent classes: `MhfeClient` (encryption,
recovery, the check, rekey, hidden wallets, the search for missing words of a container phrase and
the self-test), `MhfeRepair`, `MhfePasswords` and `MhfeWallet`. A page has none of the
protections of the operating system described above: no private screen, no locked memory, no
control of crash reports and no isolation of its own.

- The package fetches nothing and needs no `connect-src`; it works under a policy that allows
  scripts only by hash, WebAssembly and `blob:` workers. The page passes its files to each class
  as text and bytes.
- Every operation runs in a worker of its own, which is terminated when the operation ends; that
  frees the Argon2 memory. The worker is a boundary for responsiveness and cancellation, not a
  vault: it runs in the page's browser process and origin. A cancelled operation is stopped at
  once, and its memory is freed without being overwritten; so is the work area of an Argon2 round
  that fails, which the C code leaves unwiped in the browser.
- Two kinds of work hold secrets in workers for longer. A session of hidden wallets keeps its
  worker with its Argon2 work area, the main wallet's BIP39 passphrase and the passwords used so
  far, which it needs to refuse a password used twice, until the page closes it; `close()`
  overwrites them before the worker ends, and a close while a wallet opens stops the worker at
  once instead. A new phrase with the wallet check is drawn in one worker, one trial after another,
  from the browser's random generator (`crypto.getRandomValues`), and the worker ends with the
  draw.
- A password, a BIP39 passphrase, a phrase and dice rolls given to a class are copied into UTF-8
  bytes only after the class's check at start has passed and every setting is checked. The copies
  are transferred to the worker, so that none stays with the class, and are wiped when the
  operation cannot start; a `Uint8Array` the page passes is copied, not emptied. Text with an
  unpaired surrogate is refused instead of being silently changed by the browser. In the worker,
  the Rust code takes these bytes into buffers that it wipes, and it wipes the copies it holds of
  the keys and states, as far as WebAssembly allows; a result that holds a secret is written into a buffer of its final size, which is
  wiped once the result has become a JavaScript string.
- What the page holds as a JavaScript string cannot be wiped, since browsers cannot erase strings:
  a password or phrase typed into the page, a recovered or new phrase, the phrase shown to the
  owner to confirm a rekey, the phrases of hidden wallets, a generated password and the words of a
  check word review. Pass passwords and passphrases as `Uint8Array` where possible, keep such
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
