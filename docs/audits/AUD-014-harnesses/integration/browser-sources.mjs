// Load the authoritative source files in place; do not copy or build the project.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const root = new URL("../../../../", import.meta.url);
export const readBytes = (path) => readFileSync(new URL(path, root));
export const source = (path) => readBytes(path).toString("utf8");
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const dataUrl = (text) => `data:text/javascript;base64,${Buffer.from(text).toString("base64")}`;
const runtimeSource = source("web/runtime.js");
const runtimeUrl = dataUrl(runtimeSource);
const walletSource = source("web/wallet.js");
export const runtime = await import(runtimeUrl);
export const { MhfeWallet } = await import(
  dataUrl(walletSource.replaceAll('"../runtime/runtime.js"', JSON.stringify(runtimeUrl)))
);
export const sourceHashes = {
  "web/runtime.js": sha256(runtimeSource),
  "web/wallet.js": sha256(walletSource),
};

// A valid empty module exercises host compilation without invoking MHFE.
export const wasmBytes = () => Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0);
