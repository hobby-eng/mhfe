// AUD-010 secrets-security probe (CHECK-SEC-003): no network code in the browser package or the
// Rust sources outside `mhfe serve`.
//
// Scans every script of dist/ and web/ for APIs that reach a network or load remote code, wider
// than the build's own list in scripts/remove-network-code.mjs, and classifies each match: a match
// is accepted only when its surrounding text is one of the reviewed, local-only uses listed in
// ACCEPTED below. Scans the Rust sources for std::net and other socket use outside
// src/bin/mhfe/serve.rs. Prints every match with its classification and exits 1 when any match is
// unclassified.
//
//   node docs/audits/AUD-010-harnesses/secrets-security/network-scan.mjs
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

/** APIs that send or receive over a network, or load code or data from a URL. */
const PATTERNS = [
  ["fetch", /\bfetch\s*\(/gu],
  ["XMLHttpRequest", /\bXMLHttpRequest\b/gu],
  ["WebSocket", /\bWebSocket\b/gu],
  ["EventSource", /\bEventSource\b/gu],
  ["sendBeacon", /\bsendBeacon\b/gu],
  ["WebTransport", /\bWebTransport\b/gu],
  ["RTCPeerConnection", /\bRTCPeerConnection\b/gu],
  ["importScripts", /\bimportScripts\s*\(/gu],
  ["dynamic import", /\bimport\s*\(/gu],
  ["remote URL literal", /["'`]https?:\/\//gu],
  ["new Worker", /\bnew\s+(Shared)?Worker\s*\(/gu],
  ["new URL", /\bnew\s+URL\s*\(/gu],
  ["window.open", /\bwindow\.open\s*\(/gu],
  ["form submit", /\.submit\s*\(/gu],
  ["image src", /\.src\s*=/gu],
];

/**
 * Reviewed matches: the file name ending, the pattern name, and a text that must surround the
 * match (within 200 characters before and after). Each is local-only.
 */
const ACCEPTED = [
  // The runtime starts each operation's worker from a Blob URL it made itself.
  ["runtime.js", "new Worker", 'new Worker(this.#url, { name: "mhfe" })'],
  // Emscripten's pthread pool: a lane worker from mainScriptUrlOrBlob, which the core passes as a
  // Blob of the same Argon2 script (web/core-worker.js startArgon2).
  ["argon2-mt.js", "new Worker", "pthreadMainJs=URL.createObjectURL(pthreadMainJs)"],
  // Emscripten's script directory: a string operation, nothing is loaded from it.
  ["argon2-mt.js", "new URL", 'scriptDirectory=new URL(".",_scriptName).href'],
  ["argon2-st.js", "new URL", 'scriptDirectory=new URL(".",_scriptName).href'],
  // Emscripten's Node.js file reader (ENVIRONMENT_IS_NODE only): a local file, never a URL fetch.
  ["argon2-mt.js", "new URL", "isFileURI(filename)?new URL(filename):filename;var ret=fs.readFileSync"],
  ["argon2-st.js", "new URL", "isFileURI(filename)?new URL(filename):filename;var ret=fs.readFileSync"],
  // wasm-bindgen's no-modules glue names its own script; the loader that used it was removed.
  ["worker.js", "new URL", "script_src = new URL(document.currentScript.src, location.href)"],
];

function scripts(directory) {
  const found = [];
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) found.push(...scripts(path));
    else if (/\.(m?js|d\.ts)$/u.test(name)) found.push(path);
  }
  return found;
}

let unclassified = 0;
let accepted = 0;
const files = [...scripts("dist"), ...scripts("web")];
for (const file of files) {
  const text = readFileSync(file, "utf8");
  for (const [name, pattern] of PATTERNS) {
    for (const match of text.matchAll(pattern)) {
      const around = text.slice(Math.max(0, match.index - 200), match.index + 200);
      const known = ACCEPTED.some(
        ([ending, patternName, context]) =>
          file.endsWith(ending) && patternName === name && around.includes(context),
      );
      const line = text.slice(0, match.index).split("\n").length;
      if (known) {
        accepted += 1;
        console.log(`accepted  ${file}:${line} ${name}`);
      } else {
        unclassified += 1;
        console.log(`UNCLASSIFIED ${file}:${line} ${name}: ${around.replace(/\s+/gu, " ").slice(150, 260)}`);
      }
    }
  }
}
console.log(`${files.length} scripts scanned, ${accepted} reviewed local-only matches.`);

// Rust: sockets only in the fast-mode server.
const RUST_NETWORK = [/\bstd::net\b/u, /\bTcpStream\b/u, /\bUdpSocket\b/u, /\bTcpListener\b/u, /\blibc::socket\b/u, /\bconnect\s*\(/u];
function rustFiles(directory) {
  const found = [];
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) found.push(...rustFiles(path));
    else if (name.endsWith(".rs")) found.push(path);
  }
  return found;
}
for (const file of rustFiles("src")) {
  const lines = readFileSync(file, "utf8").split("\n");
  // The unit tests of a file: from `#[cfg(test)]` directly above `mod tests` to the end.
  const testsStart = lines.findIndex(
    (text, index) => text.trim() === "#[cfg(test)]" && /^\s*(pub\(crate\) )?mod tests\b/u.test(lines[index + 1] ?? ""),
  );
  lines.forEach((text, index) => {
    for (const pattern of RUST_NETWORK) {
      if (!pattern.test(text)) continue;
      // serve.rs is the localhost server; protect.rs probes that a socket is refused and closes it.
      const reviewed =
        file.endsWith("src/bin/mhfe/serve.rs") ||
        (file.endsWith("src/bin/mhfe/protect.rs") && /socket|SYS_socket/u.test(text));
      const testOnly = testsStart !== -1 && index > testsStart;
      if (reviewed || testOnly) {
        accepted += 1;
        if (testOnly && !reviewed) console.log(`test-only ${file}:${index + 1}: ${text.trim()}`);
      } else {
        unclassified += 1;
        console.log(`UNCLASSIFIED ${file}:${index + 1}: ${text.trim()}`);
      }
    }
  });
}

if (unclassified > 0) {
  console.log(`FAILED: ${unclassified} unclassified network matches.`);
  process.exit(1);
}
console.log("PASSED: no network code outside the reviewed local-only uses and src/bin/mhfe/serve.rs.");
