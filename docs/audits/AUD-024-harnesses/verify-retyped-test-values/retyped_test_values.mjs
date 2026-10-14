// AUD-024, verifier role verify-retyped-test-values, at commit b6fca69: checks the candidate
// finding that the JavaScript tooling types shared test data and helpers again instead of
// importing them from the modules that hold them. Run from the repository root:
//
//   node docs/audits/AUD-024-harnesses/verify-retyped-test-values/retyped_test_values.mjs
//
// It imports only the side-effect-free modules (public-test-data.mjs, page-values.mjs,
// test-values.mjs) and reads the others as text. Prints PRESENT or ABSENT per part, then
// DEFECT REPRODUCED and exit 1 while any part is present, or DEFECT NOT REPRODUCED and exit 0.
import { readdirSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const root = pathToFileURL(`${process.cwd()}/`);
const text = (path) => readFileSync(new URL(path, root), "utf8");
const pub = await import(new URL("scripts/public-test-data.mjs", root));
const page = await import(new URL("scripts/browser-check/page-values.mjs", root));
const tv = await import(new URL("scripts/package-check/test-values.mjs", root));
const decode = (bytes) => new TextDecoder().decode(bytes);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const parts = [];
const part = (name, present) => {
  parts.push(present);
  console.log(`${present ? "PRESENT" : "ABSENT "}  ${name}`);
};
const lineOf = (file, needle) => {
  const lines = text(file).split("\n");
  const index = lines.findIndex((line) => line.includes(needle));
  return index < 0 ? "-" : `${file}:${index + 1}`;
};

// P1: ZERO_24 defined in page-values.mjs although public-test-data.mjs exports it.
const pv = "scripts/browser-check/page-values.mjs";
part(
  `P1 ZERO_24 defined again (${lineOf(pv, "export const ZERO_24")}) with the value of ${lineOf("scripts/public-test-data.mjs", "export const ZERO_24")}`,
  /export const ZERO_24 =/u.test(text(pv)) && same(page.ZERO_24, pub.ZERO_24),
);

// P2: the known-answer cost list typed in three files.
const costs = '"1024/1", "65536/3", "262144/2"';
const costFiles = [
  "scripts/package-check/test-values.mjs",
  "scripts/verify-cli-browser-parity.mjs",
  "scripts/verify-browsers.mjs",
].filter((file) => text(file).includes(costs));
part(`P2 known-answer costs typed in ${costFiles.map((f) => lineOf(f, costs)).join(", ")}`, costFiles.length > 1);

// P3: the parity check keeps its own loader, Argon2 stand-in, page-message reader and encoders.
const par = "scripts/verify-cli-browser-parity.mjs";
const bodyOf = (file, name) => {
  const source = text(file);
  const at = source.indexOf(`function ${name}(`);
  return source.slice(source.indexOf("{", at), source.indexOf("\n}\n", at) + 2);
};
const flatBody = (file, name) => bodyOf(file, name).replace(/\s+/gu, " ");
// The two bodies with their assertion messages (the third argument of assert.throws) set aside.
const packageErrorBody = flatBody(par, "packageError").replace(
  "`${what}: the package refuses with ${code}`",
  "MESSAGE",
);
const pageMessageBody = flatBody("scripts/package-check/module-bindings.mjs", "pageMessageOf").replace(
  "}, code, );",
  "}, MESSAGE, );",
);
part(
  `P3a packageError (${lineOf(par, "function packageError")}) has the body of pageMessageOf (${lineOf("scripts/package-check/module-bindings.mjs", "function pageMessageOf")}) but its assertion message`,
  packageErrorBody === pageMessageBody,
);
part(
  `P3b the parity check loads the glue, the WebAssembly and the single-threaded Argon2 itself (${lineOf(par, 'read("target/wasm-bindgen/mhfe.js")')}) as package.mjs does (${lineOf("scripts/package-check/package.mjs", 'read("target/wasm-bindgen/mhfe.js")')}), importing nothing of package-check`,
  text(par).includes('read("target/wasm-bindgen/mhfe.js")') && !text(par).includes("package-check/"),
);
part(
  `P3c known-answers-only Argon2 at ${lineOf(par, "const knownAnswersOnly")} and ${lineOf("scripts/package-check/module-bindings.mjs", "const noArgon2")}`,
  text(par).includes("const knownAnswersOnly") &&
    text("scripts/package-check/module-bindings.mjs").includes("const noArgon2"),
);
part(
  `P3d encode/noBytes at ${lineOf(par, "const encode =")} beside ${lineOf("scripts/package-check/test-values.mjs", "export const encode =")}`,
  text(par).includes("const encode = (text) => new TextEncoder().encode(text);") &&
    text(par).includes("const noBytes = () => new Uint8Array();"),
);

// P4: build-browser-check.mjs types the public phrase, password, container and address.
const bbc = "scripts/build-browser-check.mjs";
part(
  `P4 ${bbc} types PHRASE (${lineOf(bbc, "const PHRASE")}), FULL_SIZE_CONTAINER (${lineOf(bbc, pub.FULL_SIZE_CONTAINER)}) and the BIP84 address (${lineOf(bbc, tv.PHRASE_ADDRESS)}), importing nothing of public-test-data.mjs`,
  text(bbc).includes(`'${pub.PHRASE}'`) &&
    text(bbc).includes(`'${pub.FULL_SIZE_CONTAINER}'`) &&
    text(bbc).includes(`'${tv.PHRASE_ADDRESS}'`) &&
    !text(bbc).includes("public-test-data"),
);

// P5: the bundled class files listed three times.
const flat = (file) => text(file).replace(/\s+/gu, " ");
const classList = '"core/client.js", "repair/repair.js", "passwords/passwords.js", "wallet/wallet.js",';
const classFiles = [
  "scripts/verify-browsers.mjs",
  "scripts/build-browser-check.mjs",
  "scripts/package-check/page-classes.mjs",
].filter((file) => flat(file).includes(classList));
part(`P5 class-file list in ${classFiles.map((f) => lineOf(f, '"core/client.js"')).join(", ")}`, classFiles.length > 1);

// P6: page-values.mjs and test-values.mjs define the same values.
const pairs = [
  ["CHECKED_PHRASE", page.CHECKED_PHRASE, tv.CHECKED_PHRASE],
  ["PASSWORD", page.PASSWORD, decode(tv.PASSWORD)],
  ["NEW_PASSWORD", page.NEW_PASSWORD, decode(tv.NEW_PASSWORD)],
  ["BIP84 address", page.BIP84_ADDRESS, tv.PHRASE_ADDRESS],
  ["BIP84 TREZOR address", page.BIP84_TREZOR_ADDRESS, tv.PHRASE_TREZOR_ADDRESS],
  ["fingerprint", page.FINGERPRINTS.phrase, tv.PHRASE_FINGERPRINT],
  ["TREZOR fingerprint", page.FINGERPRINTS.phraseWithTrezor, tv.PHRASE_TREZOR_FINGERPRINT],
  ["SUITE_3", page.SUITE_3, tv.SUITE_3],
  ["SUITE_4", page.SUITE_4, tv.SUITE_4],
  ["WALLET_PASSPHRASE_REQUIRED", page.WALLET_PASSPHRASE_REQUIRED, tv.WALLET_PASSPHRASE_REQUIRED],
  ["REKEY_PASSPHRASE_ONLY_WITH_REFERENCE", page.REKEY_PASSPHRASE_ONLY_WITH_REFERENCE, tv.REKEY_PASSPHRASE_ONLY_WITH_REFERENCE],
];
const imports = text(pv).includes("test-values.mjs");
const equal = pairs.filter(([, a, b]) => same(a, b)).map(([name]) => name);
part(`P6 ${equal.length} of ${pairs.length} values typed in both ${pv} and test-values.mjs: ${equal.join(", ")}`, !imports && equal.length > 0);

// P7: class-self-checks.mjs retypes the page parts' labels beside the imported part().
const csc = "scripts/package-check/class-self-checks.mjs";
part(
  `P7 ${csc} defines pagePart with its own label table (${lineOf(csc, "const pagePart")}) though it imports part() of self-checks.mjs, whose LABELS (public-test-data.mjs:109-111) hold the same labels`,
  /import \{[^}]*\bpart\b[^}]*\} from "\.\/self-checks\.mjs"/su.test(text(csc)) &&
    text(csc).includes('"browser-features": "Browser features",') &&
    ["browser-features", "package-parts", "page-encoding"].every((id) =>
      text(csc).includes(`"${id}": "${pub.SELF_CHECK_PARTS.labels[id]}"`),
    ),
);

// P8: no "deliberate copy" marker anywhere in the tooling's modules (the copy gate itself aside).
let markers = 0;
for (const dir of ["scripts", "scripts/browser-check", "scripts/package-check"]) {
  for (const file of readdirSync(new URL(`${dir}/`, root))) {
    if (file.endsWith(".mjs") && file !== "verify-no-copies.mjs") {
      markers += (text(`${dir}/${file}`).match(/deliberate copy/giu) ?? []).length;
    }
  }
}
part(`P8 no "deliberate copy" marker in the .mjs tooling (found ${markers})`, markers === 0);

const present = parts.filter(Boolean).length;
console.log(`${present} of ${parts.length} parts present`);
if (present > 0) {
  console.log("DEFECT REPRODUCED");
  process.exit(1);
}
console.log("DEFECT NOT REPRODUCED");
