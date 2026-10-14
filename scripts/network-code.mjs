// The code that could reach the network or load further code, which no script of the browser
// package may contain: one list for scripts/remove-network-code.mjs, which checks each generated
// script as the build writes it, and scripts/verify-browser-package.mjs, which checks every
// script of the finished package (AUD-023-BLD008). Tools that embed the package, such as the
// wallet tools, refuse a page that contains fetch or XMLHttpRequest at all.

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
  [/\bRTCPeerConnection\b/u, "new RTCPeerConnection()"],
  // An image, script or frame given an address loads it.
  [/\.src\s*=[^=]/u, 'image.src = "https://x"'],
];

/** A script that must pass every pattern: what the package's own scripts do. */
export const CLEAN =
  "const worker = new Worker(URL.createObjectURL(new Blob([source]))); if (a.src === b) run();";

/** The first pattern of NETWORK_CODE that `text` contains, or undefined. */
export function networkCodeIn(text) {
  return NETWORK_CODE.map(([pattern]) => pattern).find((pattern) => pattern.test(text));
}

/** Each sample is found and the clean script passes, so that the list can fail. */
export function checkNetworkCodeList() {
  for (const [pattern, sample] of NETWORK_CODE) {
    if (networkCodeIn(sample) !== pattern) throw new Error(`${pattern} does not find ${sample}`);
  }
  const found = networkCodeIn(CLEAN);
  if (found !== undefined) throw new Error(`${found} finds network code in a clean script`);
}
