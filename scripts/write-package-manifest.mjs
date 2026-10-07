// Writes dist/modules.json and dist/README.md for the browser package that scripts/build-wasm.sh
// built: the package version, its build (scripts/stamp-build-id.mjs), and for the runtime and each
// module its files with their SHA-256, so that a page that takes some modules can check exactly the
// files it takes.
//
//   node scripts/write-package-manifest.mjs dist
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [packageDir] = process.argv.slice(2);
const cargo = readFileSync("Cargo.toml", "utf8");
const version = /^version = "([^"]+)"/mu.exec(cargo)[1];
// The build stamped into the WebAssembly's custom section "mhfe-build".
const [buildSection] = WebAssembly.Module.customSections(
  new WebAssembly.Module(readFileSync(join(packageDir, "runtime/mhfe.wasm"))),
  "mhfe-build",
);
if (buildSection === undefined) throw new Error("runtime/mhfe.wasm is not stamped with its build.");
const buildId = new TextDecoder().decode(buildSection);

/** The files of one folder of the package, sorted, with their SHA-256. */
function filesOf(folder) {
  const names = readdirSync(join(packageDir, folder)).sort();
  return Object.fromEntries(
    names.map((name) => [
      name,
      createHash("sha256")
        .update(readFileSync(join(packageDir, folder, name)))
        .digest("hex"),
    ]),
  );
}

const modules = ["core", "repair", "passwords", "wallet"];
const manifest = {
  version,
  buildId,
  runtime: { files: filesOf("runtime") },
  modules: Object.fromEntries(
    modules.map((name) => [name, { files: filesOf(name), requires: ["runtime"] }]),
  ),
};
writeFileSync(join(packageDir, "modules.json"), `${JSON.stringify(manifest, null, 2)}\n`);

const sums = (folder, files) =>
  Object.entries(files)
    .map(([name, hash]) => `${hash}  ${folder}/${name}`)
    .join("\n");
const lines = [
  sums("runtime", manifest.runtime.files),
  ...modules.map((name) => sums(name, manifest.modules[name].files)),
].join("\n");
const readme = `${readFileSync("docs/BROWSER-PACKAGE.md", "utf8")}\n## SHA-256 of this build\n\nVersion ${version}, build ${buildId}.\n\n\`\`\`text\n${lines}\n\`\`\`\n`;
writeFileSync(join(packageDir, "README.md"), readme);
