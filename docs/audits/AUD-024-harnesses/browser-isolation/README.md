# AUD-024 browser-isolation harnesses

Checks kept by the browser-isolation role of audit AUD-024, a review-only audit of commit
b6fca69238344dd2525b06270ee6ff3b055e68c1 (branch `aud023-remediation`). Each check states the
expected behaviour and exits 1 when the snapshot does not meet it, 0 when it does; at b6fca69 every
check below exits 1. They read the built browser package in `dist/` (rebuilt from the snapshot by
`scripts/build-wasm.sh`) and the sources; they write nothing into the repository. Public test data
only: BIP39's all-zero phrases, the test password `public test password` and the BIP39 test
passphrase `TREZOR`. No Argon2 runs at the suite's cost: `in-process-worker.mjs` runs every
Argon2 round at 256 KiB and one pass and lets only the build's known answers (1 MiB) through.

Run every command from the repository root. Node.js 26 and Python 3.8 or later; the launcher
checks need `MHFE`, an `mhfe` program built from the snapshot (for example with
`CARGO_TARGET_DIR=<folder> cargo build --locked --release --bin mhfe`).

| File | What it checks |
| ---- | -------------- |
| `in-process-worker.mjs` | Support, no check: runs `dist/` in Node with the package's own `runtime/worker.js` in this process as each class's Worker. |
| `check-passphrase-beside-stated-length.mjs` | `MhfeClient.check()` refuses a non-empty BIP39 passphrase beside `{ words: 12 }`, and in an `onNoLength` answer `{ words: 12, passphrase }`, as `searchWallet()` refuses one beside `{ builtInCheck: true }`. |
| `check-late-answer-callback-failure.mjs` | A rekey's owner callback that fails after `cancel()` is not swallowed, as an `onProgress` that fails after `cancel()` is not. |
| `check-network-code-list.mjs` | `scripts/network-code.mjs` finds navigation, `window.open`, Service Worker registration, the Cache API, a Worker or SharedWorker from a URL, `setAttribute("src")`, `src`/`srcset`/`href`/`action` assignments, a prefixed `RTCPeerConnection`, `eval` and `new Function`. |
| `check_launcher_request_parity.py` | `mhfe serve` and `packaging/mhfe-fast-mode.py` answer six raw request heads alike, and neither serves a Host header that is not exactly `127.0.0.1:<port>`. |
| `check-launcher-checksum-size.sh` | Both launchers refuse, with `✗ Error:` and exit code 2, a checksum file of one valid line followed by 1 MiB of empty lines. |

## Commands and expected output at b6fca69

```sh
node --no-warnings docs/audits/AUD-024-harnesses/browser-isolation/check-passphrase-beside-stated-length.mjs
```

Two `ok` lines (the controls), then `FAIL a passphrase beside { words: 12 } in check() is refused`
(it resolves `"outcome":"matches"` and the worker got `words=12, passphrase of 6 bytes`) and
`FAIL an onNoLength answer { words: 12, passphrase } is refused`; exit 1.

```sh
node --no-warnings docs/audits/AUD-024-harnesses/browser-isolation/check-late-answer-callback-failure.mjs
```

`ok   control: onProgress failing after cancel() is not swallowed`, then
`FAIL the owner callback failing after cancel() is not swallowed` with `unhandled rejections: []`;
exit 1.

```sh
node --no-warnings docs/audits/AUD-024-harnesses/browser-isolation/check-network-code-list.mjs
```

`ok   fetch (control)` and fifteen `FAIL` lines; exit 1.

```sh
MHFE=<mhfe> python3 docs/audits/AUD-024-harnesses/browser-isolation/check_launcher_request_parity.py
```

`ok   control: the exact Host`, then five `FAIL` lines: a Host value ending in U+001F and a Host
field name led by U+001C (mhfe serve 403, Python 200), a request line ending in two CR (400 and
200), a UTF-8 header value (200 and 400) and a bare-LF end before a CRLF end (200 and 403); exit 1.

```sh
MHFE=<mhfe> docs/audits/AUD-024-harnesses/browser-isolation/check-launcher-checksum-size.sh
```

`FAIL mhfe serve accepts a checksum file of 1048652 bytes (exit 124)` and the same for
`mhfe-fast-mode.py`, each followed by its "SHA-256 of tool.html verified" and "Fast mode is
running" lines (the port differs from run to run); exit 1.
