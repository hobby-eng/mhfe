// AUD-024, role gap-1-fast-mode-launchers-real-browser, reviewed commit b6fca69.
//
// The documented route to the fast mode, end to end: `mhfe serve --no-browser <page>` and
// `python3 packaging/mhfe-fast-mode.py --no-browser <page>` serve a page next to its
// mhfe-fast-mode.sha256 on 127.0.0.1, and Playwright Chromium and Firefox open the printed address.
// Reduced cost only: every page runs the classes' startup and full self-checks (Argon2 at 1, 64 and
// 256 MiB), never selfTest() or a full-size operation. Every address of the browser-check page
// carries "#check", so that a page that runs at all runs only its full self-checks.
//
//   node docs/audits/AUD-024-harnesses/gap-1-fast-mode-launchers-real-browser/fast-mode-route.mjs \
//     --mhfe <mhfe binary> --work <scratch folder> [--browser chromium|firefox] \
//     [--launcher rust|python] [--stale <folder of an existing page and its checksum file>]
//
// Exits 1 when a check fails, 2 for a refused command line.
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { chromium, firefox } from "playwright";

const BROWSERS = { chromium, firefox };
const LAUNCHERS = ["rust", "python"];
const SEVEN_HEADERS = {
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-embedder-policy": "require-corp",
  "content-security-policy": "frame-ancestors 'none'",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
};
// The policy BROWSER-PACKAGE.md:48-49 says the package works under.
const DOCUMENTED_MINIMAL_POLICY = (hash) =>
  `default-src 'none'; script-src '${hash}' 'wasm-unsafe-eval'; connect-src 'none'; worker-src blob:`;
// Text that only the browser-check page holds, to find it in a browser's disk cache.
const CHECK_PAGE_MARKER = "full-size encryption gives the native container";
const CACHE_CONTROL_MARKER = "AUD024-GAP1-CACHED-CONTROL-PAGE";
const PAGE_TIMEOUT_MS = 600_000;

const { values: options } = parseArgs({
  options: {
    mhfe: { type: "string" },
    work: { type: "string" },
    repo: { type: "string", default: process.cwd() },
    browser: { type: "string" },
    launcher: { type: "string" },
    stale: { type: "string" },
  },
});
if (
  options.mhfe === undefined ||
  options.work === undefined ||
  (options.browser !== undefined && !Object.hasOwn(BROWSERS, options.browser)) ||
  (options.launcher !== undefined && !LAUNCHERS.includes(options.launcher))
) {
  console.error(
    "usage: fast-mode-route.mjs --mhfe <binary> --work <folder> [--browser chromium|firefox] " +
      "[--launcher rust|python] [--stale <folder>]",
  );
  process.exit(2);
}
const repo = resolve(options.repo);
const work = resolve(options.work);
const failures = [];
const expect = (condition, description) => {
  console.log(`${condition ? "ok  " : "FAIL"}  ${description}`);
  if (!condition) failures.push(description);
};
const note = (text) => console.log(`      ${text}`);

const pages = await buildPages();
const sink = await startSink();
try {
  for (const browserName of options.browser ? [options.browser] : Object.keys(BROWSERS)) {
    for (const launcher of options.launcher ? [options.launcher] : LAUNCHERS) {
      await routeChecks(browserName, launcher);
      await probePages(browserName, launcher);
    }
  }
} finally {
  sink.server.closeAllConnections();
  sink.server.close();
}
console.log(failures.length === 0 ? "RESULT: PASS" : `RESULT: FAIL (${failures.length})`);
for (const failure of failures) console.log(`  failed: ${failure}`);
process.exit(failures.length === 0 ? 0 : 1);

/** The pages to serve, each in a folder of its own beside its mhfe-fast-mode.sha256. */
async function buildPages() {
  // The repository's own browser-check page, built by verbatim copies of its two scripts over the
  // repository's dist/, so that nothing is written into target/.
  const copy = join(work, "repo-copy");
  rmSync(copy, { recursive: true, force: true });
  mkdirSync(join(copy, "scripts"), { recursive: true });
  for (const name of ["build-browser-check.mjs", "bundle-browser-classes.mjs"]) {
    copyFileSync(join(repo, "scripts", name), join(copy, "scripts", name));
    const same = sha256(readFileSync(join(repo, "scripts", name))) ===
      sha256(readFileSync(join(copy, "scripts", name)));
    expect(same, `the copy of scripts/${name} is byte-identical`);
  }
  symlinkSync(join(repo, "dist"), join(copy, "dist"));
  execFileSync(process.execPath, [join(copy, "scripts", "build-browser-check.mjs")], {
    stdio: "inherit",
  });
  const check = join(copy, "target", "browser-check");
  const checkHtml = readFileSync(join(check, "index.html"), "utf8");
  note(`check page: ${sha256(checkHtml)} (${checkHtml.length} bytes)`);

  // The same page under the policy BROWSER-PACKAGE.md gives as enough.
  const hash = /'(sha256-[A-Za-z0-9+/=]+)'/u.exec(checkHtml)[1];
  const minimal = checkHtml.replace(
    /(<meta http-equiv="Content-Security-Policy" content=")[^"]*(")/u,
    `$1${DOCUMENTED_MINIMAL_POLICY(hash)}$2`,
  );
  const minimalFolder = pageFolder("minimal-policy", "index.html", minimal);

  return {
    check,
    minimal: minimalFolder,
    probe: pageFolder("probe", "probe.html", await probePage()),
    stale: options.stale === undefined ? null : resolve(options.stale),
  };
}

/** Writes `html` as `name` into work/<folder>, with its checksum file; returns the folder. */
function pageFolder(folder, name, html) {
  const path = join(work, folder);
  rmSync(path, { recursive: true, force: true });
  mkdirSync(path, { recursive: true });
  writeFileSync(join(path, name), html);
  writeFileSync(join(path, "mhfe-fast-mode.sha256"), `${sha256(html)}  ${name}\n`);
  return path;
}

/**
 * A page of the four classes under the package's page policy (pagePolicy of
 * scripts/bundle-browser-classes.mjs) that runs startupCheck() and fullCheck() of every class and
 * leaves the reports in window.mhfeProbe.
 */
function probePage() {
  const moduleUrl = pathToFileURL(join(repo, "scripts", "bundle-browser-classes.mjs")).href;
  return import(moduleUrl).then(({ bundleClasses, inline, pagePolicy }) => {
    const root = pathToFileURL(`${repo}/`);
    const read = (path) => readFileSync(join(repo, path));
    const classes = bundleClasses(root, [
      "core/client.js",
      "repair/repair.js",
      "passwords/passwords.js",
      "wallet/wallet.js",
    ]);
    const probe = `
const WORKER_SOURCE = ${inline(read("dist/runtime/worker.js").toString())};
const WASM_BASE64 = ${inline(read("dist/runtime/mhfe.wasm").toString("base64"))};
const ARGON2_THREADED = ${inline(read("dist/core/argon2-mt.js").toString())};
const ARGON2_SINGLE_THREADED = ${inline(read("dist/core/argon2-st.js").toString())};
(async () => {
  const out = {
    crossOriginIsolated: self.crossOriginIsolated === true,
    sharedArrayBuffer: typeof SharedArrayBuffer,
    violations: [],
    reports: [],
  };
  document.addEventListener('securitypolicyviolation', (event) =>
    out.violations.push(event.effectiveDirective + ' ' + event.blockedURI));
  try {
    const wasm = await WebAssembly.compile(Uint8Array.from(atob(WASM_BASE64), (c) => c.charCodeAt(0)));
    const client = new MhfeClient({ workerSource: WORKER_SOURCE, wasm, argon2Threaded: ARGON2_THREADED, argon2SingleThreaded: ARGON2_SINGLE_THREADED });
    out.mode = client.mode();
    const parts = { workerSource: WORKER_SOURCE, wasm };
    const classes = [['MhfeClient', client], ['MhfeRepair', new MhfeRepair(parts)], ['MhfePasswords', new MhfePasswords(parts)], ['MhfeWallet', new MhfeWallet(parts)]];
    for (const tier of ['startupCheck', 'fullCheck']) {
      for (const [name, instance] of classes) {
        const started = performance.now();
        const report = await instance[tier]();
        out.reports.push({ name, tier: report.tier, passed: report.passed, ms: Math.round(performance.now() - started), components: report.components });
      }
    }
  } catch (error) {
    out.error = (error.code ?? '') + ' ' + error.message;
  }
  window.mhfeProbe = out;
  document.title = 'DONE';
})();
`;
    const script = `${classes}\n${probe}`;
    return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="Content-Security-Policy" content="${pagePolicy(script)}" />
    <title>running</title>
  </head>
  <body>
    <script type="module">${script}</script>
  </body>
</html>
`;
  });
}

function sha256(data) {
  return createHash("sha256").update(data).digest("hex");
}

/** Starts a launcher on the page in `folder`; resolves to its address, process and output. */
async function startLauncher(kind, folder) {
  const html = readdirSync(folder).find((name) => name.endsWith(".html"));
  const page = join(folder, html);
  const command =
    kind === "rust"
      ? [options.mhfe, ["serve", "--no-browser", page]]
      : ["python3", [join(repo, "packaging", "mhfe-fast-mode.py"), "--no-browser", page]];
  const child = spawn(command[0], command[1], {
    env: { ...process.env, NO_COLOR: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  const exited = new Promise((done) => child.on("exit", (code, signal) => done({ code, signal })));
  const address = await new Promise((done, fail) => {
    const look = (chunk) => {
      output += chunk;
      const found = /Open (http:\/\/127\.0\.0\.1:\d+\/) in your browser\./u.exec(output);
      if (found) done(found[1]);
    };
    child.stdout.on("data", look);
    child.stderr.on("data", look);
    exited.then(() => fail(new Error(`the ${kind} launcher ended: ${output}`)));
    setTimeout(() => fail(new Error(`no address from the ${kind} launcher: ${output}`)), 20_000);
  });
  return {
    address,
    output: () => output,
    async stop() {
      child.kill(kind === "python" ? "SIGINT" : "SIGTERM");
      const ended = await Promise.race([exited, sleep(5000, null)]);
      if (ended === null) child.kill("SIGKILL");
      return ended ?? (await exited);
    },
  };
}

/** A loopback server that records every connection and request, and serves the test pages. */
async function startSink() {
  const record = { connections: 0, requests: [], upgrades: [] };
  const server = createServer((request, response) => {
    record.requests.push({ url: request.url, headers: request.headers });
    const url = new URL(request.url, "http://sink");
    const target = url.searchParams.get("target") ?? "";
    const html = (body, headers = {}) => {
      response.writeHead(200, { "Content-Type": "text/html; charset=utf-8", ...headers });
      response.end(body);
    };
    switch (url.pathname) {
      case "/plain":
        return html("<!doctype html><title>plain</title><p>plain</p>");
      case "/frame":
        return html(`<!doctype html><title>frame</title><iframe src="${attr(target)}"></iframe>`);
      case "/sniff":
        return html(
          `<!doctype html><title>sniff</title><script>window.scriptLoad = 'pending';</script>` +
            `<script src="${attr(target)}" onload="window.scriptLoad='load'" ` +
            `onerror="window.scriptLoad='error'"></script>` +
            `<link rel="stylesheet" href="${attr(target)}" onload="window.styleLoad='load'" ` +
            `onerror="window.styleLoad='error'">`,
        );
      case "/html-without-nosniff":
        return html("<p>not a script</p>");
      case "/cached":
        return html(`<!doctype html><title>cached</title><p>${CACHE_CONTROL_MARKER}</p>`, {
          "Cache-Control": "max-age=3600",
        });
      case "/landing":
        return html("<!doctype html><title>landing</title><p>landing</p>");
      default:
        response.writeHead(404, { "Content-Type": "text/plain" });
        return response.end("not found\n");
    }
  });
  server.on("connection", () => {
    record.connections += 1;
  });
  server.on("upgrade", (request, socket) => {
    record.upgrades.push({ url: request.url });
    socket.destroy();
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  return { server, record, port: server.address().port };
}

function attr(text) {
  return text.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;");
}

/** A server whose page may be cached, closed later: the control of the no-store check. */
async function startCacheControlServer() {
  const server = createServer((request, response) => {
    response.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "max-age=3600",
    });
    response.end(`<!doctype html><title>cached</title><p>${CACHE_CONTROL_MARKER}</p>`);
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  return server;
}

/** Every check of the route on the browser-check page through one launcher in one browser. */
async function routeChecks(browserName, launcherKind) {
  const label = `${browserName}/${launcherKind}`;
  console.log(`\n=== ${label}: the browser-check page served by the ${launcherKind} launcher`);
  const profile = join(work, "profiles", `${browserName}-${launcherKind}`);
  rmSync(profile, { recursive: true, force: true });
  mkdirSync(profile, { recursive: true });
  const context = await BROWSERS[browserName].launchPersistentContext(profile, { headless: true });
  note(`browser version ${context.browser()?.version() ?? "(persistent context)"}`);
  const launcher = await startLauncher(launcherKind, pages.check);
  const port = Number(new URL(launcher.address).port);
  note(`launcher output:\n${launcher.output().replace(/^/gmu, "        ")}`);
  const workers = [];
  const consoleLines = [];
  const pageErrors = [];
  const requests = [];
  context.on("request", (request) => requests.push(request.url()));
  const page = context.pages()[0] ?? (await context.newPage());
  page.on("worker", (worker) => workers.push(worker.url()));
  page.on("console", (message) => consoleLines.push(`${message.type()}: ${message.text()}`));
  page.on("pageerror", (error) => pageErrors.push(String(error)));
  try {
    // 1. The browser's own request: Host, status and the seven headers.
    const response = await page.goto(`${launcher.address}#check`);
    const headers = await response.allHeaders();
    const sent = await response.request().allHeaders();
    expect(response.status() === 200, `${label}: the browser's request is answered 200`);
    note(`request headers the browser reports: ${JSON.stringify(sent)}`);
    for (const [name, value] of Object.entries(SEVEN_HEADERS)) {
      expect(headers[name] === value, `${label}: header ${name}: ${value} (got ${headers[name]})`);
    }

    // 2. Cross-origin isolation with the page's meta policy.
    const state = await page.evaluate(() => ({
      crossOriginIsolated: self.crossOriginIsolated,
      sharedArrayBuffer: typeof SharedArrayBuffer,
      policy: document.querySelector('meta[http-equiv="Content-Security-Policy"]').content,
    }));
    expect(state.crossOriginIsolated === true, `${label}: the page is crossOriginIsolated`);
    expect(state.sharedArrayBuffer === "function", `${label}: SharedArrayBuffer exists`);
    note(`meta policy: ${state.policy.replace(/sha256-[^']+/u, "sha256-…")}`);

    // 3. The page's own run: mode, threaded build and the full self-check of every class.
    await page.waitForFunction(() => ["PASS", "FAIL"].includes(document.title), null, {
      timeout: PAGE_TIMEOUT_MS,
    });
    const log = await page.textContent("#log");
    note(`page log:\n${log.trimEnd().replace(/^/gmu, "        ")}`);
    expect((await page.title()) === "PASS", `${label}: the browser-check page says PASS`);
    expect(log.includes("mode: fast, protocol: http:"), `${label}: the client is in fast mode`);
    expect(
      /Argon2id at 64 and 256 MiB, threaded build: passed/u.test(log),
      `${label}: the threaded build's full check passed`,
    );
    expect(!/: warning/u.test(log), `${label}: no part passed only as a warning`);
    note(`workers seen by Playwright (${workers.length}): ${summarize(workers)}`);
    expect(workers.length > 0, `${label}: Playwright saw the page's workers`);
    expect(workers.every((url) => url.startsWith("blob:")), `${label}: every worker is a blob:`);
    expect(pageErrors.length === 0, `${label}: no uncaught page error (${pageErrors.join("; ")})`);
    // Until here only the page ran: it may have asked for nothing but itself and Blob workers.
    const ownRequests = requests.filter((url) => url !== launcher.address && !url.startsWith("blob:"));
    note(`requests of the page's own run: ${summarize(requests)}`);
    expect(ownRequests.length === 0, `${label}: the page's own run requested nothing else (${ownRequests.join(", ")})`);

    // 4. Nothing reaches the network: fetch, WebSocket, image, beacon, EventSource, script,
    // style, frame, import and workers from a URL, from the page and from a Blob worker.
    await networkProbes(page, label);

    // 5. A wrong Host, as the browser sends it for another name of this computer.
    const other = await page.goto(`http://localhost:${port}/#check`).catch((error) => error);
    const otherStatus = other instanceof Error ? other.message.split("\n")[0] : other.status();
    note(`http://localhost:${port}/ gives ${otherStatus}`);
    expect(otherStatus === 403, `${label}: the Host localhost:${port} is refused with 403`);

    // 6. frame-ancestors 'none' and X-Frame-Options from another site, with a control.
    await framingCheck(context, label, launcher.address);
    // 7. nosniff: the page used as a script and a style sheet from another site.
    await nosniffCheck(context, label, launcher.address);
    // 8. no-referrer: a navigation from the page, against one from a page without the header.
    await referrerCheck(page, label, launcher.address);
    // 9. no-store: once the launcher has stopped, the page is gone; a cacheable page is not.
    await noStoreCheck(page, label, launcher);
  } finally {
    await launcher.stop();
    await context.close();
  }
  // 10. Neither the page nor a part of it is in the browser's disk cache; the control page is.
  const checkFound = folderHolds(profile, CHECK_PAGE_MARKER);
  const controlFound = folderHolds(profile, CACHE_CONTROL_MARKER);
  note(`disk cache: control page found: ${controlFound}, browser-check page found: ${checkFound}`);
  if (controlFound) {
    expect(!checkFound, `${label}: the no-store page is not in the browser's disk cache`);
  } else {
    note("the control page is not on disk either: the disk-cache scan shows nothing here");
  }
  if (consoleLines.length > 0) note(`console of the page:\n${consoleLines.join("\n")}`);
  note(`requests seen: ${summarize(requests)}`);
}

function summarize(urls) {
  const counts = new Map();
  for (const url of urls) {
    const key = url.startsWith("blob:") ? "blob:<page origin>/<uuid>" : url;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts].map(([url, count]) => `${url} x${count}`).join(", ");
}

/** Every way the probe tries to reach the sink; none may arrive. */
async function networkProbes(page, label) {
  const before = sink.record.requests.length;
  const connectionsBefore = sink.record.connections;
  const target = `http://127.0.0.1:${sink.port}`;
  const outcome = await page.evaluate(async (sinkOrigin) => {
    const violations = [];
    document.addEventListener("securitypolicyviolation", (event) =>
      violations.push(`${event.effectiveDirective} ${event.blockedURI}`),
    );
    const results = {};
    const settle = (executor) =>
      new Promise((done) => {
        setTimeout(() => done("no answer in 3 s"), 3000);
        try {
          executor(done);
        } catch (error) {
          done(`threw ${error.name}: ${error.message}`);
        }
      });
    const attempt = async (name, run) => {
      try {
        results[name] = await run();
      } catch (error) {
        results[name] = `threw ${error.name}: ${error.message}`;
      }
    };
    await attempt("fetch", () => fetch(`${sinkOrigin}/p-fetch`).then((r) => `status ${r.status}`));
    await attempt("websocket", () =>
      settle((done) => {
        const socket = new WebSocket(`${sinkOrigin.replace("http", "ws")}/p-websocket`);
        socket.onopen = () => done("open");
        socket.onerror = () => done("error event");
      }),
    );
    await attempt("image", () =>
      settle((done) => {
        const image = new Image();
        image.onload = () => done("loaded");
        image.onerror = () => done("error event");
        image.src = `${sinkOrigin}/p-image.png`;
      }),
    );
    await attempt("beacon", () => (navigator.sendBeacon(`${sinkOrigin}/p-beacon`, "x") ? "queued" : "refused"));
    await attempt("eventsource", () =>
      settle((done) => {
        const source = new EventSource(`${sinkOrigin}/p-eventsource`);
        source.onopen = () => done("open");
        source.onerror = () => done("error event");
      }),
    );
    await attempt("script", () =>
      settle((done) => {
        const script = document.createElement("script");
        script.onload = () => done("loaded");
        script.onerror = () => done("error event");
        script.src = `${sinkOrigin}/p-script.js`;
        document.head.append(script);
      }),
    );
    await attempt("stylesheet", () =>
      settle((done) => {
        const link = document.createElement("link");
        link.rel = "stylesheet";
        link.onload = () => done("loaded");
        link.onerror = () => done("error event");
        link.href = `${sinkOrigin}/p-style.css`;
        document.head.append(link);
      }),
    );
    await attempt("iframe", () =>
      settle((done) => {
        const frame = document.createElement("iframe");
        frame.onload = () => done("load event");
        frame.src = `${sinkOrigin}/p-frame`;
        document.body.append(frame);
      }),
    );
    await attempt("import", () => import(`${sinkOrigin}/p-import.js`).then(() => "imported"));
    await attempt("worker from a same-origin URL", () =>
      settle((done) => {
        const worker = new Worker("/p-worker.js");
        worker.onerror = () => done("error event");
      }),
    );
    await attempt("worker from the sink's URL", () =>
      settle((done) => {
        const worker = new Worker(`${sinkOrigin}/p-worker.js`);
        worker.onerror = () => done("error event");
      }),
    );
    // A Blob worker, as the package's workers are, and a Blob worker nested in it, as the
    // threaded Argon2 build's lane workers are: each tries the network itself.
    const nested = `
      const found = [];
      self.addEventListener('securitypolicyviolation', (e) => found.push(e.effectiveDirective));
      fetch('__SINK__/n-fetch').then(() => 'fetched', (e) => 'fetch ' + e.name).then((r) => setTimeout(() => postMessage({ fetch: r, violations: found }), 300));`;
    const outer = `
      const results = {};
      const found = [];
      self.addEventListener('securitypolicyviolation', (e) => found.push(e.effectiveDirective + ' ' + e.blockedURI));
      const sink = ${JSON.stringify(sinkOrigin)};
      (async () => {
        try { const r = await fetch(sink + '/w-fetch'); results.fetch = 'status ' + r.status; } catch (e) { results.fetch = 'threw ' + e.name; }
        try { importScripts(sink + '/w-import.js'); results.importScripts = 'imported'; } catch (e) { results.importScripts = 'threw ' + e.name; }
        // Code from strings: the policy has no 'unsafe-eval' ('wasm-unsafe-eval' only).
        try { results.eval = 'ran: ' + eval('1 + 1'); } catch (e) { results.eval = 'threw ' + e.name; }
        try { results.newFunction = 'ran: ' + new Function('return 2')(); } catch (e) { results.newFunction = 'threw ' + e.name; }
        results.websocket = await new Promise((done) => {
          setTimeout(() => done('no answer'), 3000);
          try { const s = new WebSocket(sink.replace('http', 'ws') + '/w-websocket'); s.onopen = () => done('open'); s.onerror = () => done('error event'); } catch (e) { done('threw ' + e.name); }
        });
        results.workerFromUrl = await new Promise((done) => {
          setTimeout(() => done('no answer'), 3000);
          try { const w = new Worker(location.origin + '/w-worker.js'); w.onerror = () => done('error event'); } catch (e) { done('threw ' + e.name + ': ' + e.message); }
        });
        results.nestedBlobWorker = await new Promise((done) => {
          setTimeout(() => done('no answer'), 5000);
          try {
            const source = ${JSON.stringify(nested)}.replace('__SINK__', sink);
            const w = new Worker(URL.createObjectURL(new Blob([source], { type: 'text/javascript' })));
            w.onmessage = (e) => done(e.data);
            w.onerror = (e) => done('error event ' + e.message);
          } catch (e) { done('threw ' + e.name + ': ' + e.message); }
        });
        setTimeout(() => postMessage({ results, violations: found }), 300);
      })();`;
    await attempt("blob worker", () =>
      new Promise((done) => {
        setTimeout(() => done("no answer in 15 s"), 15000);
        const blob = new Blob([outer], { type: "text/javascript" });
        const worker = new Worker(URL.createObjectURL(blob));
        worker.onmessage = (event) => done(event.data);
        worker.onerror = (event) => done(`error event ${event.message}`);
      }),
    );
    await new Promise((done) => setTimeout(done, 500));
    return { results, violations };
  }, target);
  await sleep(1500);
  const arrived = sink.record.requests.slice(before);
  for (const [name, result] of Object.entries(outcome.results)) {
    note(`${name}: ${JSON.stringify(result)}`);
  }
  note(`page violations: ${outcome.violations.join(", ")}`);
  note(`sink: ${arrived.length} requests, ${sink.record.connections - connectionsBefore} connections`);
  expect(arrived.length === 0, `${label}: no probe request reached the sink`);
  expect(sink.record.connections === connectionsBefore, `${label}: no probe connected to the sink`);
  expect(sink.record.upgrades.length === 0, `${label}: no WebSocket upgrade reached the sink`);
  const inWorker = outcome.results["blob worker"]?.results ?? {};
  expect(
    String(inWorker.eval).startsWith("threw") && String(inWorker.newFunction).startsWith("threw"),
    `${label}: eval and new Function are refused in a Blob worker of the page`,
  );
}

/** frame-ancestors 'none': the page in a frame of another site does not render. */
async function framingCheck(context, label, address) {
  const attacker = await context.newPage();
  const lines = [];
  attacker.on("console", (message) => lines.push(message.text()));
  try {
    const frameTitle = async (target) => {
      await attacker.goto(
        `http://localhost:${sink.port}/frame?target=${encodeURIComponent(target)}`,
      );
      await sleep(3000);
      const child = attacker.frames().find((frame) => frame !== attacker.mainFrame());
      // A frame the browser blocked may never answer an evaluation (Firefox): 5 s at most.
      const title =
        child === undefined
          ? "no child frame"
          : await Promise.race([
              child
                .evaluate(() => `${document.title} at ${location.href}`)
                .catch((error) => `not readable: ${error.message.split("\n")[0]}`),
              sleep(5000, "no answer from the frame in 5 s"),
            ]);
      return { url: child?.url(), title };
    };
    const control = await frameTitle(`http://127.0.0.1:${sink.port}/plain`);
    const framed = await frameTitle(`${address}#check`);
    note(`control frame: ${JSON.stringify(control)}`);
    note(`launcher frame: ${JSON.stringify(framed)}`);
    note(`console: ${lines.join(" | ")}`);
    expect(/^plain at /u.test(control.title ?? ""), `${label}: a control frame renders`);
    expect(
      !/^(running|PASS|FAIL) at http:\/\/127\.0\.0\.1/u.test(framed.title ?? ""),
      `${label}: the served page does not render in another site's frame`,
    );
    expect(
      lines.some((line) => /frame-ancestors|X-Frame-Options/iu.test(line)),
      `${label}: the browser names frame-ancestors or X-Frame-Options`,
    );
  } finally {
    await attacker.close();
  }
}

/**
 * nosniff. A page of another site that loads the served page as a script or style sheet is
 * refused by Chromium's opaque-response blocking with or without nosniff, so that case is only
 * recorded. The effect of nosniff itself shows on a same-origin load: the launcher's 404 answer is
 * a document of the page's origin with no script policy, and from it the page "/" is loaded as a
 * script and a style sheet. Without nosniff a browser runs text/html as a script (the control, from
 * the sink, with a page error); with it the browser refuses it for its type.
 */
async function nosniffCheck(context, label, address) {
  const attacker = await context.newPage();
  try {
    const attempt = async (document, script) => {
      const lines = [];
      const errors = [];
      const listener = (message) => lines.push(message.text());
      const errorListener = (error) => errors.push(String(error));
      attacker.on("console", listener);
      attacker.on("pageerror", errorListener);
      await attacker.goto(document);
      const flags = await attacker.evaluate(
        (source) =>
          new Promise((done) => {
            const flags = {};
            const settle = () => {
              if (Object.keys(flags).length === 2) done(flags);
            };
            const element = document.createElement("script");
            element.onload = () => ((flags.script = "load"), settle());
            element.onerror = () => ((flags.script = "error"), settle());
            element.src = source;
            document.head.append(element);
            const link = document.createElement("link");
            link.rel = "stylesheet";
            link.onload = () => ((flags.style = "load"), settle());
            link.onerror = () => ((flags.style = "error"), settle());
            link.href = source;
            document.head.append(link);
            setTimeout(() => done(flags), 4000);
          }),
        script,
      );
      await sleep(500);
      attacker.off("console", listener);
      attacker.off("pageerror", errorListener);
      return { flags, lines, errors };
    };
    const crossSite = await attempt(
      `http://localhost:${sink.port}/plain`,
      address,
    );
    const control = await attempt(
      `http://127.0.0.1:${sink.port}/plain`,
      `http://127.0.0.1:${sink.port}/html-without-nosniff`,
    );
    const served = await attempt(`${address}no-such-path`, "/");
    note(`cross-site page loading the served page: ${JSON.stringify(crossSite)}`);
    note(`control, same origin, text/html without nosniff: ${JSON.stringify(control)}`);
    note(`same origin as the served page, "/" with nosniff: ${JSON.stringify(served)}`);
    expect(crossSite.flags.script !== "load", `${label}: another site cannot run the page as a script`);
    expect(served.flags.script === "error", `${label}: the page as a same-origin script is refused`);
    expect(served.errors.length === 0, `${label}: the page was never run as a script`);
    expect(
      served.lines.some((line) => /nosniff|strict MIME/iu.test(line)),
      `${label}: the browser names nosniff or strict MIME checking for the page`,
    );
  } finally {
    await attacker.close();
  }
}

/** no-referrer: a navigation that leaves the page carries no Referer, against a control. */
async function referrerCheck(page, label, address) {
  const follow = async (from, tag) => {
    await page.goto(from);
    const before = sink.record.requests.length;
    await page.evaluate((url) => {
      const link = document.createElement("a");
      link.href = url;
      document.body.append(link);
      link.click();
    }, `http://localhost:${sink.port}/landing?from=${tag}`);
    await page.waitForURL(/\/landing\?/u);
    const request = sink.record.requests.slice(before).find((entry) => entry.url.startsWith("/landing"));
    return { referer: request?.headers.referer ?? null, documentReferrer: await page.evaluate(() => document.referrer) };
  };
  const control = await follow(`http://127.0.0.1:${sink.port}/plain`, "control");
  // The page runs its #check run when loaded; the link leaves it at once.
  const served = await follow(`${address}#check`, "launcher");
  note(`control navigation: ${JSON.stringify(control)}`);
  note(`navigation from the served page: ${JSON.stringify(served)}`);
  expect(control.referer !== null, `${label}: the control navigation carries a Referer`);
  expect(
    served.referer === null && served.documentReferrer === "",
    `${label}: a navigation from the served page carries no Referer`,
  );
}

/** no-store: with the launcher stopped the page cannot be shown; a cacheable control page can. */
async function noStoreCheck(page, label, launcher) {
  const control = await startCacheControlServer();
  const controlUrl = `http://127.0.0.1:${control.address().port}/cached`;
  await page.goto(controlUrl);
  await page.goto(`http://127.0.0.1:${sink.port}/cached`);
  await page.goto(`http://127.0.0.1:${sink.port}/plain`);
  control.closeAllConnections();
  await new Promise((done) => control.close(done));
  const controlAgain = await page.goto(controlUrl).then(
    async (response) => `status ${response?.status()}, ${(await page.content()).includes(CACHE_CONTROL_MARKER) ? "marker shown" : "no marker"}`,
    (error) => `failed: ${error.message.split("\n")[0]}`,
  );
  await page.goto(`${launcher.address}#check`);
  await page.waitForFunction(() => ["PASS", "FAIL"].includes(document.title), null, {
    timeout: PAGE_TIMEOUT_MS,
  });
  await page.goto(`http://127.0.0.1:${sink.port}/plain`);
  const ended = await launcher.stop();
  note(`launcher stopped: ${JSON.stringify(ended)}; its output:\n${launcher.output().replace(/^/gmu, "        ")}`);
  const pageAgain = await page.goto(`${launcher.address}#check`).then(
    (response) => `status ${response?.status()}`,
    (error) => `failed: ${error.message.split("\n")[0]}`,
  );
  note(`cacheable control page after its server closed: ${controlAgain}`);
  note(`served page after the launcher stopped: ${pageAgain}`);
  if (controlAgain.includes("marker shown")) {
    expect(pageAgain.startsWith("failed"), `${label}: the no-store page is not shown from a cache`);
  } else {
    note("the control page was not shown from the cache either: this check shows nothing here");
  }
}

/** Whether any file below `folder` holds `text`. */
function folderHolds(folder, text) {
  const needle = Buffer.from(text);
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) {
        if (walk(child)) return true;
      } else if (entry.isFile() && statSync(child).size < 64 * 1024 * 1024) {
        if (readFileSync(child).includes(needle)) return true;
      }
    }
    return false;
  };
  return walk(folder);
}

/** The probe page (startupCheck and fullCheck of every class), the minimal-policy page and the
 * existing page, each served by the launcher in a fresh page. */
async function probePages(browserName, launcherKind) {
  const browser = await BROWSERS[browserName].launch({ headless: true });
  note(`browser ${browserName} ${browser.version()}`);
  try {
    const probeFolder = pages.probe;
    const list = [
      ["probe", probeFolder],
      ["minimal-policy", pages.minimal],
      ...(pages.stale === null ? [] : [["existing target page", pages.stale]]),
    ];
    for (const [name, folder] of list) {
      const label = `${browserName}/${launcherKind}/${name}`;
      console.log(`\n=== ${label}`);
      const launcher = await startLauncher(launcherKind, folder);
      const page = await browser.newPage();
      const workers = [];
      const lines = [];
      page.on("worker", (worker) => workers.push(worker.url()));
      page.on("console", (message) => lines.push(`${message.type()}: ${message.text()}`));
      try {
        const response = await page.goto(`${launcher.address}#check`);
        expect(response.status() === 200, `${label}: served`);
        await page.waitForFunction(() => ["PASS", "FAIL", "DONE"].includes(document.title), null, {
          timeout: PAGE_TIMEOUT_MS,
        });
        if (name === "probe") {
          await probeOutcome(page, label);
        } else {
          const log = await page.textContent("#log");
          note(`page log:\n${log.trimEnd().replace(/^/gmu, "        ")}`);
          const passed = (await page.title()) === "PASS" && log.includes("mode: fast");
          if (name === "existing target page") {
            note(`existing page: ${passed ? "PASS in fast mode" : "did not pass"} (informational)`);
          } else {
            expect(passed, `${label}: PASS in fast mode`);
            expect(
              /threaded build: passed/u.test(log),
              `${label}: the threaded build's full check passed`,
            );
          }
        }
        note(`workers: ${summarize(workers)}`);
        if (lines.length > 0) note(`console:\n${lines.join("\n")}`);
      } finally {
        await page.close();
        await launcher.stop();
      }
    }
  } finally {
    await browser.close();
  }
}

/** The startup and full reports of every class on the probe page. */
async function probeOutcome(page, label) {
  const out = await page.evaluate(() => window.mhfeProbe);
  expect(out.error === undefined, `${label}: no error (${out.error})`);
  expect(out.crossOriginIsolated === true && out.mode === "fast", `${label}: isolated, fast mode`);
  // Firefox asks for /favicon.ico for every page it shows; the page's img-src 'none' refuses it
  // before any request, which the page reports as a violation of its own. That one is the
  // browser's, not the package's, and is only noted.
  const favicon = (entry) => /^img-src http:\/\/127\.0\.0\.1:\d+\/favicon\.ico$/u.test(entry);
  const browserOwn = out.violations.filter(favicon);
  if (browserOwn.length > 0) note(`the browser's own favicon request refused: ${browserOwn.join(", ")}`);
  const violations = out.violations.filter((entry) => !favicon(entry));
  expect(violations.length === 0, `${label}: no policy violation (${violations.join(", ")})`);
  for (const report of out.reports) {
    const outcomes = report.components.map((part) => `${part.id}=${part.outcome}`).join(" ");
    note(`${report.name} ${report.tier} in ${report.ms} ms: ${outcomes}`);
    for (const part of report.components) {
      if (part.detail !== undefined) note(`  ${part.id}: ${part.detail}`);
    }
    expect(report.passed, `${label}: ${report.name} ${report.tier} passed`);
    const warned = report.components.filter((part) => part.outcome === "warning");
    expect(warned.length === 0, `${label}: ${report.name} ${report.tier} has no warning`);
  }
  const client = out.reports.find((report) => report.name === "MhfeClient" && report.tier === "startup");
  const argon2 = client?.components.find((part) => part.id === "argon2");
  expect(argon2?.outcome === "passed", `${label}: the startup Argon2 part passed on the threaded build`);
  const full = out.reports.find((report) => report.name === "MhfeClient" && report.tier === "full");
  const threaded = full?.components.find((part) => part.id === "argon2-sizes-threaded");
  expect(threaded?.outcome === "passed", `${label}: argon2-sizes-threaded passed`);
}
