// Enumerate the actual accepted package namespaces; no operation or full-cost check is run.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { bindings } from "../../../scripts/package-check/package.mjs";
import { loadClasses } from "../../../scripts/package-check/page-classes.mjs";

const classes = await loadClasses();
const names = (object) =>
  Reflect.ownKeys(object)
    .map((key) => (typeof key === "symbol" ? key.toString() : key))
    .sort();
const exports = (namespace) =>
  Object.entries(namespace).map(([name, value]) => {
    const record = { name, kind: typeof value };
    if (typeof value !== "function") return record;
    const prototypes = [];
    let object = value.prototype;
    while (object && object !== Object.prototype && object !== Error.prototype) {
      prototypes.push({
        owner: Object.getOwnPropertyDescriptor(object, "constructor")?.value?.name ?? "inherited",
        members: names(object),
      });
      object = Object.getPrototypeOf(object);
    }
    return { ...record, staticNames: names(value), prototypes };
  });
const record = {
  auditId: "AUD-032",
  method:
    "Reflect actual current package namespaces and public prototype names; no getters invoked or operation instances constructed.",
  classes: exports(
    Object.fromEntries(Object.entries(classes).filter(([name]) => name !== "runtime")),
  ),
  runtime: exports(classes.runtime),
  rawWasmBindingNamespace: exports(bindings),
  sourceDeclarations: Object.fromEntries(
    [
      "web/client.d.ts",
      "web/repair.d.ts",
      "web/passwords.d.ts",
      "web/wallet.d.ts",
      "web/runtime.d.ts",
    ].map((path) => [path, createHash("sha256").update(readFileSync(path)).digest("hex")]),
  ),
  limits:
    "Names/constructors/inherited members are mechanical inventory, not counts of independent features or semantic proof. Types, callback DTOs, Rust API families and guarantees are reviewed separately. Native standard Error/Object inherited members are omitted.",
};
assert.ok(record.classes.some(({ name }) => name === "MhfeClient"));
assert.ok(record.runtime.some(({ name }) => name === "requireInputText"));
assert.ok(record.rawWasmBindingNamespace.some(({ name }) => name === "wordHints"));
writeFileSync(process.argv[2], `${JSON.stringify(record, null, 2)}\n`, { flag: "wx" });
console.log(
  JSON.stringify({
    classNamespaceMembers: record.classes.length,
    runtimeExports: record.runtime.length,
    rawNamespaceEntries: record.rawWasmBindingNamespace.length,
  }),
);
