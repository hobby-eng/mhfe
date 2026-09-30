# MHFE browser package

This package runs MHFE suite 3 (`MHFE-BIP39-256-EXPERIMENTAL-3`) in a web page: it encrypts an
English BIP39 recovery phrase into a 24-word container, recovers the phrase, and rehearses a
recovery without showing the phrase. All the MHFE logic is the same Rust code as in the `mhfe`
command-line tool; Argon2 is the same reference C code, compiled to WebAssembly.

It is experimental and has not been independently reviewed. Do not use it to protect real funds.

## Files

| File                | What it is                                                               |
| ------------------- | ------------------------------------------------------------------------ |
| `client.js`         | The page-side client, an ES module; `client.d.ts` describes its API      |
| `mhfe-worker.js`    | The worker: the Rust core's glue, the Argon2 bridge and the worker logic |
| `mhfe_core_bg.wasm` | The Rust core                                                            |
| `argon2-mt.js`      | Argon2 with four threads, for cross-origin isolated pages                |
| `argon2-st.js`      | Argon2 with one thread, for every other page, including `file://`        |

Nothing is fetched at run time. The page passes the files to the client as text and bytes, so it
works under a Content-Security-Policy such as
`default-src 'none'; script-src 'sha256-...' 'wasm-unsafe-eval'; connect-src 'none'; worker-src blob:`.

## Use

```js
import { MhfeClient } from "./client.js";

const client = new MhfeClient({
  workerSource, // text of mhfe-worker.js
  argon2Threaded, // text of argon2-mt.js
  argon2SingleThreaded, // text of argon2-st.js
  coreWasm, // mhfe_core_bg.wasm as a Uint8Array or a WebAssembly.Module
});

const { container } = await client.encrypt({
  phrase,
  password,
  passwordRepeat, // the password typed a second time; a difference is refused
  onProgress: ({ round, rounds }) => showProgress(round, rounds),
  // After 12 of the 24 rounds: show it, marked as not yet verified, while the check runs.
  onUnverified: ({ container }) => showUnverified(container),
});
// Resolved only after the check has passed; a failed check rejects with VERIFICATION_FAILED.

const recovery = await client.decrypt({ container, password });
// recovery.kind is "phrase" or, very rarely, "ambiguous"; show every candidate then.

const { matches } = await client.check({ container, password, reference: { address } });
```

An encryption decrypts its container's words again and compares the result with the phrase, so it
runs 24 rounds and takes twice as long as a recovery; `onProgress` reports `rounds` as 24 then, and
12 for `decrypt` and `check`. The promise resolves only after this check has passed. So that the
user can write the container down meanwhile, `onUnverified` receives it after the first 12 rounds.

Each operation runs in a new worker, which is terminated when the operation ends; this also frees
the 2 GiB of Argon2 memory. `client.cancel()` stops a running operation at once. Only one operation
runs at a time.

## Fast and standard mode

`client.mode()` returns `"fast"` when the page is cross-origin isolated and `"standard"` otherwise.
In fast mode the four Argon2 lanes run in parallel threads: a recovery takes about one to two
minutes. In standard mode they run one after another, about four to seven minutes. An encryption
takes twice as long in either mode. A page opened as a file is never isolated; `mhfe serve
<page.html>` serves it from this computer with the headers that make it isolated. On a computer
without the mhfe program, the package's `mhfe-fast-mode.py` does the same with Python 3.8 or later
and nothing else.

Both launchers serve a page only when the checksum file `mhfe-fast-mode.sha256` lies next to it:
one line in the format `sha256sum` writes, the page's SHA-256, two spaces and its file name. Ship
that file beside the tool's HTML file, always under this name. Without it, with another file name
in it or with a different SHA-256, the launcher refuses with a message and serves nothing. Started
without arguments, as by a double-click, a launcher serves the page named in the
`mhfe-fast-mode.sha256` next to itself; `mhfe serve <page.html>` and
`python3 mhfe-fast-mode.py <page.html>` serve a page elsewhere, next to its own checksum file.

## Memory

A browser gives WebAssembly at most 4 GiB, and the reference Argon2 code allows 2 GiB on 32-bit
targets, so the browser supports memory level 0 only. `client.maxSupportedMemLevel()` returns 0, and
a higher level is refused before anything starts. Use the command-line tool for higher levels.
Containers made with level 0 in the browser and on the command line are identical.

## What the page should do

The specification asks applications to do some things the client cannot do for them:

- ask for the password twice before `encrypt` (the client refuses two different entries) and advise
  a different password for each container;
- show the suite identifier when a container is made; when the PIM or memory level is not the
  default, tell the user to remember it and offer to record it, since recovery needs exactly that
  value; with the defaults, say that the 24 words and the password are enough, unless
  `otherLengths` of the phrase is not empty: then ask the user to remember the word count and to
  select it when recovering;
- if it shows the container from `onUnverified`, mark it clearly as not yet verified, and then say
  how the check ended: verified when the promise resolves, wrong and not to be used on
  `VERIFICATION_FAILED`, not verified on a cancel or any other error;
- show the words it has read back to the user in full: `client.readContainer()` and
  `client.readPhrase()` return them;
- before encrypting, look at `otherLengths` from `client.readPhrase()`: when it is not empty (about
  one phrase in four billion), tell the user to note the word count and choose it during recovery,
  because automatic detection would not give the phrase on its own;
- warn in standard mode that the operation takes longer, because the four Argon2 lanes then run one
  after another;
- start an operation only on an explicit user action and offer a cancel button.

## What the browser cannot wipe

The Rust core and the Argon2 bridge overwrite every copy of the password, the keys and the states
they hold. A password typed into a page is a JavaScript string, and so is a recovered phrase that
the page shows; the browser cannot erase strings. Pass the password as a `Uint8Array` where
possible, keep recovered phrases on screen only as long as needed, and close the tab afterwards.
