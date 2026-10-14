// Joins the runtime and module classes of the browser package in dist/ into the text of one ES
// module, as a page's build does when it inlines the package under its Content-Security-Policy:
// each class file's imports of "../runtime/runtime.js" are dropped, since the runtime's exports
// are then in the same module, and the Content-Security-Policy of such a page. Used by
// scripts/verify-browsers.mjs and scripts/build-browser-check.mjs.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const runtimeImport = /^(?:import|export) \{[^}]*\} from "\.\.\/runtime\/runtime\.js";\n/gmu;

/** The repository's root, as a URL. */
export const root = new URL("../", import.meta.url);

/** The bytes of the repository's file at `path`, from the root. */
export function read(path) {
  return readFileSync(new URL(path, root));
}

/** JSON that is safe inside a script element: "</script" cannot appear in it. */
export function inline(value) {
  return JSON.stringify(value).replaceAll("<", "\\u003c");
}

/** The runtime and the class files `paths` (relative to dist/) as one module's text. */
export function bundleClasses(root, paths) {
  const read = (path) => readFileSync(new URL(`dist/${path}`, root)).toString();
  return [
    read("runtime/runtime.js"),
    ...paths.map((path) => read(path).replace(runtimeImport, "")),
  ].join("\n");
}

/**
 * The Content-Security-Policy of a page whose one inline module is `script`, as the offline wallet
 * tools send it: nothing but that script, WebAssembly, Blob workers and inline styles. The one
 * copy of the policy for the browser suite and the browser-check page (AUD-023-ARC018).
 */
export function pagePolicy(script) {
  const scriptHash = createHash("sha256").update(script, "utf8").digest("base64");
  return [
    "default-src 'none'",
    `script-src 'sha256-${scriptHash}' 'wasm-unsafe-eval'`,
    "style-src 'unsafe-inline'",
    "img-src 'none'",
    "font-src 'none'",
    "connect-src 'none'",
    "worker-src blob:",
    "object-src 'none'",
    "frame-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
}
