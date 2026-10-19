# AUD-037 request-deadline checks

This focused follow-up starts from signed commit
`205c4547b17108ae7bf9c2b01aa803bb84a7c5c7`. Its Rust localhost launcher converted a request-read
timeout into HTTP 400 with a new response budget. The existing standalone Python launcher closes
the expired request instead.

From the repository root, with its pinned toolchain and dependencies available:

```sh
export CARGO_HOME="$PWD/../workingspace/cargo"
export RUSTUP_HOME="$PWD/../workingspace/rustup"
export CARGO_BUILD_JOBS=1
export RUST_TEST_THREADS=1
bash docs/audits/AUD-037-harnesses/checks.sh
```

The script stops on failure and otherwise exits zero. It uses public synthetic HTTP data only.
The recorded native compilation window allowed 1.5 GiB RSS, retained a 3 GiB machine reserve
and ran separately from other sessions' heavy work. The Python response test needs more than
128 MiB because it includes a 64 MiB public response; its retained rerun allows 256 MiB.

The two new Rust tests exercise the actual `answer` function and real loopback sockets:

- An already-expired request and a 50 ms kernel-read deadline return a timeout and send no
  response. The original implementation fails the first assertion by returning success after
  sending HTTP 400; its original failing receipt is retained locally in AUD-037 evidence.
- An incomplete malformed request still receives HTTP 400.

The existing 500 ms slow-client test retains its fast-GET limit of 400 ms and closure limit of
2 seconds. It additionally refuses a response to the expired request and includes receive/time
diagnostics if it fails. The other request limits, routing, security headers, checksum admission,
response deadline and connection cap remain covered by the neighboring Rust/Python tests.

Local recorded results are 21 Rust server tests, 12 selected Python routing/server tests and
Clippy. These are overlapping component suites, not a combined count of independent guarantees.
The helper script's constituent commands were recorded separately; no complete standalone
execution of this wrapper is claimed.

The original Windows EOF delay was observed in hosted CI, but its precise kernel/scheduling
cause was not measured. A Linux pass proves the local deadline policy, not Windows acceptance.
The existing native CI must also pass on the corrected commit, including Windows release/PTY
and macOS signing/PTY checks. This follow-up runs no full-cost vectors or canonical packaging,
adds no startup work and does not regenerate the browser package.
