# AUD-024 secrets-native harnesses

Harnesses of the secrets-native review of audit AUD-024 (threat model and secret ownership of the
native command-line tool), written for commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`. Each
checks one defect the review reports and exits 1 while the defect is there, 0 once it is fixed. At
b6fca69 every one of them exits 1. Public test data only: the BIP39 test phrase "abandon ... about"
or "abandon ... art", the letters "ab" and public EFF list words. None runs Argon2 at the suite's
cost: the `mhfe` commands they start stop before any secret is accepted, or run the checks at start
only.

Run them from the repository root, on Linux, with the pinned toolchain of `rust-toolchain.toml`
and Python 3. The Rust harnesses build offline from the registry cache with their own lockfile;
give cargo a target folder outside the repository. `<mhfe>` is a release build of the tool at the
commit under test (`cargo build --locked --release`), `<scratch>` a folder for temporary files on
a file system with user extended attributes (ext4, btrfs, xfs; tmpfs from Linux 6.6).

## isolation-writes

The isolation of a command that handles secrets (`protect::isolate_thread`: no_new_privs, Landlock,
seccomp) compiled from `src/bin/mhfe/protect/landlock.rs` and `seccomp.rs` as they are, and applied
as for a command started directly (a process of one thread in a user and network namespace of its
own) and as for a command of the start menu (a thread). In each it tries what the tool's own probe
tries, opening `/dev/null` for writing, then writes that need no opening for writing: an extended
attribute holding the test phrase, a mode change, a timestamp change and a truncate. SECURITY.md
says the ruleset "refuses every write to the file system".

```sh
CARGO_TARGET_DIR=<target> cargo run --offline --release \
  --manifest-path docs/audits/AUD-024-harnesses/secrets-native/isolation-writes/Cargo.toml -- <scratch>
```

Expected at b6fca69 (Linux 7.0, Landlock ABI 8): both opens refused with errno 13, `setxattr`,
`chmod` and `utimensat` ALLOWED in both cases, `truncate` refused, the test phrase read back from
the extended attributes, then `FAIL: a write to the file system got through the isolation of a
secret command` and exit 1. On a kernel with Landlock ABI 1 or 2 (Linux 5.13 to 6.1) `truncate`
gets through as well.

## zram-no-sysfs

The swap inventory of `src/bin/mhfe/protect/swap.rs`, taken as it is by `build.rs`, on made-up
`/proc`, `/dev` and `/sys` trees: a zram swap device with a sysfs entry and no `backing_dev` (A),
the same device with no `/sys` at all, as in a chroot that mounts `/proc` and `/dev` only (B), and a
plain partition without `/sys` (C, control).

```sh
CARGO_TARGET_DIR=<target> cargo run --offline --release \
  --manifest-path docs/audits/AUD-024-harnesses/secrets-native/zram-no-sysfs/Cargo.toml -- <scratch>
```

Expected at b6fca69: `A ... Available([])`, `B ... Available([])`, `C ... Available([SwapArea {
name: "/dev/sda5", unknown: false }])`, then `FAIL: a zram area whose writeback cannot be read is
taken as in memory, no warning` and exit 1.

## check-word-labels

An allocator that counts the blocks freed while they still hold a watched word, the criterion of
the repository's own regression test of AUD-023-SEC001 (`src/bin/mhfe/typed_line.rs`, module
`freed`). It runs the steps that build and draw a check-word repair answer of a password, each
copied with its format string from `src/bin/mhfe/check_word.rs` (`Action::answer`),
`src/bin/mhfe/choice.rs` (`draw_entry_rows`) and `src/bin/mhfe/style.rs` (`paint` and the styles):
these are copies, since the binary's modules cannot be linked alone, and the file names the lines.

```sh
CARGO_TARGET_DIR=<target> cargo run --offline --release \
  --manifest-path docs/audits/AUD-024-harnesses/secrets-native/check-word-labels/Cargo.toml
```

Expected at b6fca69: `choice.rs:394 paint(STRONG, label): 1 block(s) freed unwiped holding
"zookeeper"`, the other steps and controls 0, then `FAIL: 1 block(s) holding a word of the password
freed without a wipe` and exit 1.

## repair-debug

The library's `check_word::PasswordReview` of a test password with `?` in the place of its check
word, and the `Debug` text of the repair it offers, beside that of a `Password`.

```sh
CARGO_TARGET_DIR=<target> cargo run --offline --release \
  --manifest-path docs/audits/AUD-024-harnesses/secrets-native/repair-debug/Cargo.toml
```

Expected at b6fca69: `Debug of a Repair: Repair { position: 6, word: "wool", typed: 40..41 }`,
`Debug of a Password: Password(hidden)`, then `FAIL: Debug of a Repair names a word of the
password` and exit 1.

## stderr_write_errors.py

Part 1 runs `mhfe password` and `mhfe repair-words --stdin --count 4` with standard error on
`/dev/full`. Part 2 runs `mhfe encrypt --pim 0 --mem 0` in a pseudo-terminal whose standard output
and error are the terminal opened a second time with `O_NONBLOCK`; at the private screen's prompt
for the original seed phrase it stops reading and types `ab` and two Backspaces until the terminal's
output buffer is full, then reports how the tool ended and whether it left the alternate screen.

```sh
python3 -B docs/audits/AUD-024-harnesses/secrets-native/stderr_write_errors.py <mhfe>
```

Expected at b6fca69: both commands of part 1 with exit status -6 (SIGABRT); in part 2 `exit status:
-6 (SIGABRT)` and `alternate screen left after it was entered: False`; then a `FAIL:` line and exit
1.

## line_refusals.py

At the private screen's prompt for the original seed phrase of `mhfe encrypt --pim 0 --mem 0` in a
pseudo-terminal: (A) three words, which the phrase rules refuse, (B) the byte 0xff and Enter, (C)
8,200 letters without Enter. Then with `--stdin`: (D) a first line that is the byte 0xff and (E,
control) three words.

```sh
python3 -B docs/audits/AUD-024-harnesses/secrets-native/line_refusals.py <mhfe>
```

Expected at b6fca69: A asked again; B and C end the command with exit status 2 ("The answer is not
valid UTF-8 text.", "An answer is longer than 8192 bytes; ..."); D exit status 1 with "Input or
output failed: stream did not contain valid UTF-8"; E exit status 2; then a `FAIL:` line and exit 1.
