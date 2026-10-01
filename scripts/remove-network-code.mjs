// Removes the network loaders from the generated browser scripts, so that the package contains no
// code that could fetch anything, not even code that never runs.
//
//   node scripts/remove-network-code.mjs argon2 dist/argon2-mt.js dist/argon2-st.js
//   node scripts/remove-network-code.mjs glue target/wasm-bindgen/mhfe_core.js
//
// Emscripten and wasm-bindgen always emit loaders that fetch a WebAssembly file by URL. MHFE never
// uses them: the Argon2 builds embed their WebAssembly (SINGLE_FILE) and read it synchronously,
// and the worker passes the Rust core to `initSync`. Each loader is replaced by a stub that
// throws. Every replaced text must occur exactly once, so an update of either tool that changes
// it stops the build instead of leaving a loader behind. Tools that embed the package, such as the
// wallet tools, refuse a page that contains fetch or XMLHttpRequest at all.
import { readFileSync, writeFileSync } from "node:fs";

const EMBEDDED = "MHFE loads no files: its WebAssembly is embedded";

/** The minified Emscripten 6.0.10 loaders of a worker build. */
const ARGON2_REPLACEMENTS = [
  [
    'readBinary=url=>{var xhr=new XMLHttpRequest;xhr.open("GET",url,false);xhr.responseType="arraybuffer";xhr.send(null);return new Uint8Array(xhr.response)}',
    `readBinary=url=>{throw new Error("${EMBEDDED}")}`,
  ],
  [
    'readAsync=async url=>{var response=await fetch(url,{credentials:"same-origin"});if(response.ok){return response.arrayBuffer()}throw new Error(response.status+" : "+response.url)}',
    `readAsync=async url=>{throw new Error("${EMBEDDED}")}`,
  ],
];

/** Code that could reach the network. None of it may remain. */
const NETWORK_CODE = [
  /\bfetch\s*\(/u,
  /\bXMLHttpRequest\b/u,
  /\bWebSocket\b/u,
  /\bEventSource\b/u,
  /\bsendBeacon\b/u,
];

function replaceOnce(text, find, replacement, file) {
  const count = text.split(find).length - 1;
  if (count !== 1) {
    throw new Error(
      `${file}: expected the loader text exactly once, found it ${count} times: ${find.slice(0, 60)}`,
    );
  }
  return text.replace(find, () => replacement);
}

/** Cuts the text from the line that starts with `from` up to, not including, the line `to`. */
function replaceBlock(text, from, to, replacement, file) {
  const start = text.indexOf(from);
  const end = text.indexOf(to, start);
  if (start < 0 || end < 0 || text.indexOf(from, start + 1) >= 0) {
    throw new Error(
      `${file}: the wasm-bindgen loader block "${from.trim()}" was not found exactly once`,
    );
  }
  return text.slice(0, start) + replacement + text.slice(end);
}

function removeFromGlue(text, file) {
  // __wbg_load only serves __wbg_init; both go, and the asynchronous initializer that the glue
  // exports becomes a stub. initSync, which the worker uses, stays as it is.
  const withoutLoad = replaceBlock(
    text,
    "    async function __wbg_load(module, imports) {",
    "    function initSync(module) {",
    "",
    file,
  );
  return replaceBlock(
    withoutLoad,
    "    async function __wbg_init(module_or_path) {",
    "    return Object.assign(__wbg_init, { initSync }, exports);",
    "    // Loading by URL is removed: MHFE passes the module to initSync and fetches nothing.\n" +
      "    function __wbg_init() {\n" +
      `        throw new Error('${EMBEDDED}; use initSync');\n` +
      "    }\n\n",
    file,
  );
}

const [kind, ...files] = process.argv.slice(2);
if ((kind !== "argon2" && kind !== "glue") || files.length === 0) {
  throw new Error("Usage: node scripts/remove-network-code.mjs argon2|glue <file>...");
}
for (const file of files) {
  let text = readFileSync(file, "utf8");
  if (kind === "argon2") {
    for (const [find, replacement] of ARGON2_REPLACEMENTS)
      text = replaceOnce(text, find, replacement, file);
  } else {
    text = removeFromGlue(text, file);
  }
  const left = NETWORK_CODE.find((pattern) => pattern.test(text));
  if (left !== undefined) throw new Error(`${file}: network code is still present: ${left}`);
  writeFileSync(file, text);
}
