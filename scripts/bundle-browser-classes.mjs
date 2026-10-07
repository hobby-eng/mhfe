// Joins the runtime and module classes of the browser package in dist/ into the text of one ES
// module, as a page's build does when it inlines the package under its Content-Security-Policy:
// each class file's imports of "../runtime/runtime.js" are dropped, since the runtime's exports
// are then in the same module. Used by scripts/verify-browsers.mjs and
// scripts/build-browser-check.mjs.
import { readFileSync } from "node:fs";

const runtimeImport = /^(?:import|export) \{[^}]*\} from "\.\.\/runtime\/runtime\.js";\n/gmu;

/** The runtime and the class files `paths` (relative to dist/) as one module's text. */
export function bundleClasses(root, paths) {
  const read = (path) => readFileSync(new URL(`dist/${path}`, root)).toString();
  return [
    read("runtime/runtime.js"),
    ...paths.map((path) => read(path).replace(runtimeImport, "")),
  ].join("\n");
}
