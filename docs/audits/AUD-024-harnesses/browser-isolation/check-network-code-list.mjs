// AUD-024 browser-isolation check: the one list of scripts/network-code.mjs, which the build
// (scripts/remove-network-code.mjs) and the package check (scripts/package-check/manifest.mjs) use
// to keep code that "could reach the network or load further code" out of every script of the
// browser package, finds each of these samples. Each would make a request, carry data off the page
// or run code from text in a browser page or worker. Exits 1 when the list passes any sample.
import { networkCodeIn } from "../../../../scripts/network-code.mjs";

const samples = [
  ["fetch (control)", 'fetch("https://x")'],
  ["navigation by location", 'location.href = "https://x/?" + data'],
  ["navigation by location.assign", 'location.assign("https://x")'],
  ["window.open", 'window.open("https://x/?" + data)'],
  ["Service Worker registration", 'navigator.serviceWorker.register("/sw.js")'],
  ["Cache API add, which fetches", 'caches.open("c").then((cache) => cache.add("https://x"))'],
  ["a Worker from a URL", 'new Worker("https://x/w.js")'],
  ["a SharedWorker from a URL", 'new SharedWorker("https://x/w.js")'],
  ["setAttribute src", 'image.setAttribute("src", "https://x")'],
  ["src through Object.assign", 'Object.assign(new Image(), { src: "https://x" })'],
  ["srcset assignment", 'image.srcset = "https://x 1x"'],
  ["href assignment and click", 'anchor.href = "https://x"; anchor.click()'],
  ["form action and submit", 'form.action = "https://x"; form.submit()'],
  ["prefixed RTCPeerConnection", "new webkitRTCPeerConnection()"],
  ["eval", 'eval("1")'],
  ["Function constructor", 'new Function("return 1")()'],
];
let failed = false;
for (const [name, text] of samples) {
  const found = networkCodeIn(text) !== undefined;
  if (!found) failed = true;
  console.log(`${found ? "ok  " : "FAIL"} ${name} is found: ${text}`);
}
process.exit(failed ? 1 : 0);
