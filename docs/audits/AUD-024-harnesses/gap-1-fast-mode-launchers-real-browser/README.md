# AUD-024 harness: the fast-mode route in real browsers

Audit AUD-024, role gap-1-fast-mode-launchers-real-browser, reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`.

These scripts run the documented route to the browser package's fast mode end to end, at reduced
cost only: the pages run the classes' `startupCheck()` and `fullCheck()` (Argon2 at 1, 64 and
256 MiB), never `selfTest()` or a full-size operation, and every address of the browser-check page
carries `#check`. Only public test data and loopback connections are used. Each script exits
non-zero when a check fails.

## `fast-mode-route.mjs`

`mhfe serve --no-browser <page>` and `python3 packaging/mhfe-fast-mode.py --no-browser <page>`
serve a page next to its `mhfe-fast-mode.sha256` on 127.0.0.1, and Playwright Chromium and Firefox
open the address the launcher prints. For each browser and launcher it checks:

- the browser's own request (its Host header) is answered 200, with the seven headers of
  `SECURITY_HEADERS` in `src/bin/mhfe/serve.rs`, and the Host `localhost:<port>` is refused with 403;
- the page is `crossOriginIsolated` under those headers and its meta policy, the client is in fast
  mode, and the repository's browser-check page (built by verbatim copies of
  `scripts/build-browser-check.mjs` and `scripts/bundle-browser-classes.mjs` over `dist/`, written
  into the work folder, not `target/`) says PASS with the threaded Argon2 build's full check passed;
  every worker Playwright sees is a `blob:` worker, and the page's own run requests nothing but
  itself and Blob workers;
- fetch, WebSocket, an image, a beacon, EventSource, a script, a style sheet, a frame, an import and
  workers from a URL, from the page, from a Blob worker and from a Blob worker nested in it, reach no
  request or connection at a loopback sink server; `eval` and `new Function` are refused in a Blob
  worker of the page;
- `frame-ancestors 'none'`: the page does not render in a frame of another site (a control frame
  does);
- `nosniff`: the page loaded as a same-origin script is refused for its type (a control text/html
  without nosniff runs); a cross-site load is refused too;
- `no-referrer`: a navigation from the page carries no Referer (a control navigation does);
- `no-store`: once the launcher has stopped the page cannot be opened again from a cache (a
  cacheable control page can), and the page is not in the browser's disk cache (the control is);
- a probe page under the package's page policy (`pagePolicy` of
  `scripts/bundle-browser-classes.mjs`) runs `startupCheck()` and `fullCheck()` of every class: all
  pass with no warning, `argon2` passes on the threaded build and `argon2-sizes-threaded` passes;
- the browser-check page under the shorter policy of `docs/BROWSER-PACKAGE.md:48-49` passes too.

With `--stale <folder>` it also serves an existing page and its checksum file, read only, and
reports its result without counting it.

## `opener-and-menu.py`

The other documented starts: `mhfe serve <page>` with the system opener (a stand-in `xdg-open`
first on PATH records the address and opens nothing), `mhfe` without arguments beside the page in a
pseudo-terminal (the fast mode must be the first entry; Enter serves it), the same with a wrong
checksum file (the menu must say the fast mode is not offered, and why), and
`mhfe-fast-mode.py --no-browser` copied beside the page without a file argument. Each served
address must answer `GET /` with 200 and the seven headers. Linux or macOS (pty).

## `viewports.mjs`

CHECK-UI-001 for the route: the browser-check page served by `mhfe serve`, in Chromium and Firefox
at 1280x800, 1280x500, 1024x768, 800x600, 640x480, 390x844 and 390x500. Each must reach PASS in
fast mode; a screenshot of each is saved, and sideways scrolling is reported (the page is a log in a
`<pre>`; a host page owns its layout).

## `cookies.mjs`

Cookies are kept per host, not per port, so a cookie another local service sets for 127.0.0.1 goes
to the launcher too. The script gives Chromium and Firefox one cookie with a UTF-8 value, then
cookies of 20,000 bytes, and reports the status each launcher answers; it exits 1 when the two
launchers answer the same browser request differently. At b6fca69 it exits 1: the Python launcher
answers 400 to the UTF-8 cookie where `mhfe serve` serves the page (the request-head difference an
earlier wave of AUD-024 confirmed), and both answer 400 to the 20,000 bytes, beyond their 16 KiB
request-head limit.

## Inputs

- `dist/` of the reviewed commit (built by `scripts/build-wasm.sh`), `node_modules/` with Playwright
  1.64.0 and its Chromium and Firefox;
- an `mhfe` binary of the reviewed commit, for example built with
  `CARGO_TARGET_DIR=<folder> cargo build --locked --release`;
- `python3`;
- a scratch folder.

## Commands, from the repository root

```sh
node docs/audits/AUD-024-harnesses/gap-1-fast-mode-launchers-real-browser/fast-mode-route.mjs \
  --mhfe <mhfe> --work <scratch>/work --stale target/browser-check
python3 docs/audits/AUD-024-harnesses/gap-1-fast-mode-launchers-real-browser/opener-and-menu.py \
  <mhfe> <scratch>/work/repo-copy/target/browser-check <scratch>/menu-work
node docs/audits/AUD-024-harnesses/gap-1-fast-mode-launchers-real-browser/viewports.mjs \
  <mhfe> <scratch>/work/repo-copy/target/browser-check <scratch>/screenshots
node docs/audits/AUD-024-harnesses/gap-1-fast-mode-launchers-real-browser/cookies.mjs \
  <mhfe> <scratch>/work/repo-copy/target/browser-check
```

`fast-mode-route.mjs` takes `--browser chromium|firefox` and `--launcher rust|python` to keep one
of each; the other scripts use the page that it builds.

## Expected output

One `ok` line per check and `RESULT: PASS` at the end, exit code 0. Any `FAIL` line ends with
`RESULT: FAIL (<count>)` and exit code 1; a refused command line exits 2.
At b6fca69 every check of the three scripts passed with Chromium 156.0.8078.4 and Firefox 157.0
(the audit's evidence logs `g03-fast-mode-route.log`, `g04-opener-and-menu.log` and
`g06-viewports.log`). `cookies.mjs` failed as described above (`g12-cookies.log`).
