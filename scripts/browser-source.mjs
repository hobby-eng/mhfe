// Joins reviewed page-side source modules without bundling, transpilation or minification.
// Only named imports/exports are joined; the runtime import of the core stays external.
import { readFileSync } from "node:fs";

const root = new URL("../web/", import.meta.url);
const entries = { runtime: "runtime.js", client: "client.js" };
const links = /^(import|export) \{([^}]+)\} from "([^"]+)";\n?/gmu;
const declaration = /^export ((?:async )?(?:class|function|const) (\w+))/gmu;
const declared = /^(?:export )?(?:async )?(?:class|function|const) (\w+)/gmu;
// Type-only imports/aliases are checked in the separate source modules. The shipped declaration
// files own package types; source-only paths and duplicate aliases do not belong in joined JS.
const sourceTypes = /^\/\*\*\s*(?:\*\s*)?@(?:import|typedef)\b[\s\S]*?\*\/\n?/gmu;

/** Named bindings in the deliberately small source-module grammar. */
function names(text, path) {
  return text
    .split(",")
    .filter((part) => part.trim() !== "")
    .map((part) => {
      const name = part.trim();
      if (!/^[A-Za-z_$][\w$]*$/u.test(name)) {
        throw new Error(`${path}: source assembly takes named bindings without aliases.`);
      }
      return name;
    });
}

/**
 * The complete runtime or core source as shipped before build stamping. Modules stay separate
 * for lint/type review; only their import/export wiring changes here. Unknown imports, cycles,
 * duplicate declarations and missing public exports stop assembly.
 */
export function browserSource(name) {
  if (!Object.hasOwn(entries, name)) throw new Error(`Unknown browser source entry: ${name}`);
  return joinSources(new URL(entries[name], root), (path) => readFileSync(path, "utf8"));
}

/** Join a closed source graph; the reader parameter also lets controls exercise refusal paths. */
export function joinSources(entry, read) {
  const parts = new Map();
  const active = new Set();
  const publicNames = new Set();
  const externalImports = new Set();
  const externalExports = new Set();
  const declarations = new Map();
  const exportsOf = new Map();
  const edges = [];

  const visit = (path) => {
    const key = path.href;
    if (active.has(key)) throw new Error(`Browser source import cycle: ${key}`);
    if (parts.has(key)) return;
    active.add(key);
    const text = read(path);
    const exported = new Set([...text.matchAll(declaration)].map((match) => match[2]));
    exportsOf.set(key, exported);
    if (path.href === entry.href) {
      for (const match of text.matchAll(declaration)) publicNames.add(match[2]);
    }
    const body = text.replace(links, (_, kind, bindings, specifier) => {
      const listed = names(bindings, key);
      if (specifier === "../runtime/runtime.js" || specifier === "../../runtime/runtime.js") {
        for (const binding of listed) {
          (kind === "import" ? externalImports : externalExports).add(binding);
        }
        return "";
      }
      if (
        !/^\.\/(?:runtime-parts|client-parts)\/[a-z-]+\.js$/u.test(specifier) &&
        !/^\.\/[a-z-]+\.js$/u.test(specifier)
      ) {
        throw new Error(`${key}: unsupported source import ${specifier}`);
      }
      if (kind === "export" && path.href === entry.href) {
        for (const binding of listed) publicNames.add(binding);
      }
      if (kind === "export") for (const binding of listed) exported.add(binding);
      const target = new URL(specifier, path);
      edges.push({ target: target.href, bindings: listed });
      visit(target);
      return "";
    });
    if (/^(?:import\s|export\s+(?:\{|\*|default\b))/mu.test(body)) {
      throw new Error(`${key}: an import or export is outside the source assembly grammar.`);
    }
    active.delete(key);
    parts.set(key, body);
  };
  visit(entry);

  for (const { target, bindings } of edges) {
    for (const name of bindings) {
      if (!exportsOf.get(target)?.has(name)) {
        throw new Error(`Missing browser source import: ${name} from ${target}`);
      }
    }
  }

  for (const [path, body] of parts) {
    for (const match of body.matchAll(declared)) {
      const name = match[1];
      if (declarations.has(name)) throw new Error(`Duplicate browser source binding: ${name}`);
      declarations.set(name, path);
    }
  }
  for (const name of publicNames) {
    if (!declarations.has(name)) throw new Error(`Missing browser source export: ${name}`);
    if (externalExports.has(name)) throw new Error(`Duplicate browser source export: ${name}`);
  }
  for (const name of externalImports) {
    if (declarations.has(name)) throw new Error(`Duplicate browser source binding: ${name}`);
  }
  const wiring = [];
  /** @type {[string, Set<string>][]} */
  const externalLinks = [
    ["import", externalImports],
    ["export", externalExports],
  ];
  for (const [kind, bindings] of externalLinks) {
    if (bindings.size) {
      wiring.push(`${kind} { ${[...bindings].join(", ")} } from "../runtime/runtime.js";`);
    }
  }
  return [
    ...wiring,
    ...[...parts].map(
      ([path, body]) =>
        `// Source: ${new URL(path).pathname.split("/web/")[1]}\n` +
        body
          .replace(sourceTypes, "")
          .replace(/^\/\/ @ts-check\n/gmu, "")
          .replace(declaration, (whole, declaration, name) =>
            publicNames.has(name) ? whole : declaration,
          ),
    ),
  ].join("\n");
}
