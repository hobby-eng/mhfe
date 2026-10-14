// A lexical tripwire for known network loaders and dynamic code in the browser JavaScript.
// The build and package checks use the same patterns and two counted, reviewed Worker sites.
// This catches changes to those constructs; it cannot prove arbitrary code never communicates
// (AUD-024-BLD002). The package's Python launcher is a separate loopback HTTP server.

/** Each pattern with a sample that it must find; `CLEAN` must pass them all. */
export const NETWORK_CODE = [
  [/\bfetch\s*\(/u, 'fetch("x")'],
  [/\bXMLHttpRequest\b/u, "new XMLHttpRequest()"],
  [/\bWebSocket\b/u, 'new WebSocket("wss://x")'],
  [/\bEventSource\b/u, 'new EventSource("x")'],
  [/\bsendBeacon\b/u, 'navigator.sendBeacon("x")'],
  [/\bimportScripts\s*\(/u, 'importScripts("x")'],
  [/\bimport\s*\(/u, 'await import("x")'],
  [/\bWebTransport\b/u, 'new WebTransport("https://x")'],
  [/RTCPeerConnection\b/u, "new webkitRTCPeerConnection()"],
  // An image, script or frame given an address loads it.
  [/\.(?:src|srcset|href|action|data)\s*=(?!=)/u, 'image.src = "https://x"'],
  [/\b(?:src|srcset|href|action)\s*:/u, 'Object.assign(image, { src: "https://x" })'],
  [
    /\blocation(?:\.(?:href|pathname|search|hash|host|hostname|protocol))?\s*=(?!=)/u,
    'location.href = "https://x"',
  ],
  [/\blocation\.(?:assign|replace)\s*\(/u, 'location.assign("https://x")'],
  [/\bwindow\.open\s*\(/u, 'window.open("https://x")'],
  [/\bserviceWorker\b/u, 'navigator.serviceWorker.register("x")'],
  [/\bcaches\b/u, 'caches.open("x")'],
  [/\bnew\s+(?:Worker|SharedWorker)\s*\(/u, 'new Worker("https://x")'],
  [
    /\.setAttribute\s*\(\s*["'](?:src|srcset|href|action|data)["']/iu,
    'image.setAttribute("src", "https://x")',
  ],
  [/\.(?:submit|requestSubmit)\s*\(/u, "form.submit()"],
  [/\beval\s*\(/u, 'eval("1")'],
  [/\bFunction\s*\(/u, 'new Function("return 1")'],
];

/** A script that must pass every pattern: what the package's own scripts do. */
export const CLEAN = "const value = new Uint8Array(1); if (a.src === b) run();";

// Deliberate copies of the two reviewed sites: exact contexts and counts restrict the exceptions.
// checkNetworkCodeList verifies that an extra Worker or a changed context is refused.
const WORKER_SITES = {
  runtime: String.raw`this.#url = URL.createObjectURL(
    new Blob([this.#scripts.join("\n;\n")], { type: "text/javascript" }),
  );
  this.#worker = new Worker(this.#url, { name: "mhfe" });`,
  // Emscripten 6.0.12. The browser bridge supplies a Blob as mainScriptUrlOrBlob;
  // Node's package checks start the same generated script from its local filename.
  threaded:
    'var pthreadMainJs=_scriptName;if(Module["mainScriptUrlOrBlob"]){pthreadMainJs=Module["mainScriptUrlOrBlob"];if(typeof pthreadMainJs!="string"){pthreadMainJs=URL.createObjectURL(pthreadMainJs)}}worker=new Worker(pthreadMainJs,{workerData:"em-pthread",name:"em-pthread"});',
};

/** Whitespace may change at the reviewed site; its operations and arguments may not. */
function sitePattern(site) {
  const escaped = (part) => part.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(site.split(/\s+/u).map(escaped).join("\\s*"), "gu");
}

/** A forbidden pattern, or an absent/repeated reviewed site in a named script. */
export function networkCodeIn(text, workerSite) {
  let checked = text;
  if (workerSite !== undefined) {
    if (!Object.hasOwn(WORKER_SITES, workerSite))
      throw new Error(`Unknown Worker site: ${workerSite}`);
    const pattern = sitePattern(WORKER_SITES[workerSite]);
    if ([...text.matchAll(pattern)].length !== 1)
      return /missing or repeated reviewed Blob Worker site/u;
    checked = text.replace(pattern, "");
  }
  return NETWORK_CODE.map(([pattern]) => pattern).find((pattern) => pattern.test(checked));
}

/** Each sample is found and the clean script passes, so that the list can fail. */
export function checkNetworkCodeList() {
  for (const [pattern, sample] of NETWORK_CODE) {
    if (!pattern.test(sample) || networkCodeIn(sample) === undefined) {
      throw new Error(`${pattern} does not find ${sample}`);
    }
  }
  const found = networkCodeIn(CLEAN);
  if (found !== undefined) throw new Error(`${found} finds network code in a clean script`);
  for (const [name, site] of Object.entries(WORKER_SITES)) {
    if (
      networkCodeIn(site, name) !== undefined ||
      networkCodeIn(`${site}\nnew Worker("https://x")`, name) === undefined ||
      networkCodeIn(`${site}\n${site}`, name) === undefined ||
      networkCodeIn(site.replace("new Worker", "new SharedWorker"), name) === undefined
    ) {
      throw new Error(`The counted ${name} Worker exception does not decide its controls.`);
    }
  }
}
