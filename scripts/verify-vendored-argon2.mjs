// The vendored Argon2 code must be exactly the recorded upstream files: those listed with their
// SHA-256 in vendor/phc-winner-argon2.md, byte for byte, with no file missing and none added, and
// nothing in the folder but plain files and folders (AUD-023-BLD001). A file that is not listed
// would otherwise be compiled in unseen: both builds search the vendored include/ before the system
// folders, so an added include/limits.h, for one, would replace the system header in core.c.
//
//   node scripts/verify-vendored-argon2.mjs               the vendored folder against its list
//   node scripts/verify-vendored-argon2.mjs --self-test   the check against changed copies
//
// The one gate of the vendored code: scripts/check.sh runs both, scripts/build-argon2-wasm.sh runs
// the first before Emscripten compiles, and packaging/Dockerfile.reproducible before the native
// builds.

import { createHash } from "node:crypto";
import {
  cpSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
/** The vendored folder and the document that lists its files, from the repository root. */
const FOLDER = "vendor/phc-winner-argon2";
const LIST = "vendor/phc-winner-argon2.md";
/** One line of the list: the SHA-256, two spaces and the path, as sha256sum writes it. */
const LISTED_LINE = /^([0-9a-f]{64}) {2}(\S(?:.*\S)?)$/u;

/** The usage, said with a refused command line. */
const USAGE = "usage: node scripts/verify-vendored-argon2.mjs [--self-test]";

/**
 * The SHA-256 of every listed file, by its path: the lines of the document's one ```text block.
 * A line of another form, a path given twice or a document without the block is refused.
 */
function listedFiles(document) {
  const lines = document.split("\n");
  const start = lines.indexOf("```text");
  const end = lines.indexOf("```", start + 1);
  if (start < 0 || end < 0 || lines.indexOf("```text", start + 1) >= 0) {
    throw new Error(`${LIST} must hold exactly one \`\`\`text block with the SHA-256 list`);
  }
  const listed = new Map();
  for (const line of lines.slice(start + 1, end)) {
    const match = LISTED_LINE.exec(line);
    if (match === null) throw new Error(`${LIST}: not a "<SHA-256>  <path>" line: ${line}`);
    if (listed.has(match[2])) throw new Error(`${LIST}: ${match[2]} is listed twice`);
    listed.set(match[2], match[1]);
  }
  return listed;
}

/**
 * The SHA-256 of every file under `folder`, by its path from there with "/" between the names, and
 * the paths of anything that is neither a plain file nor a folder: a link, a device, a pipe.
 */
function filesIn(folder) {
  const files = new Map();
  const others = [];
  const visit = (path) => {
    for (const name of readdirSync(join(folder, path)).sort()) {
      const child = path === "" ? name : `${path}/${name}`;
      const kind = lstatSync(join(folder, child));
      if (kind.isDirectory()) {
        visit(child);
      } else if (kind.isFile()) {
        files.set(
          child,
          createHash("sha256")
            .update(readFileSync(join(folder, child)))
            .digest("hex"),
        );
      } else {
        others.push(child);
      }
    }
  };
  visit("");
  return { files, others };
}

/** What differs between the files under `folder` and the list in `document`, one line each. */
function differences(folder, document) {
  const listed = listedFiles(document);
  const { files, others } = filesIn(folder);
  const found = [];
  for (const path of others) found.push(`${path} is not a plain file`);
  for (const [path, sha256] of listed) {
    if (!files.has(path) && !others.includes(path)) found.push(`${path} is missing`);
    else if (files.has(path) && files.get(path) !== sha256) found.push(`${path} was changed`);
  }
  for (const path of files.keys()) {
    if (!listed.has(path)) found.push(`${path} is not listed`);
  }
  return found;
}

/** Checks the vendored folder of `base` against the list of `base`; true when they agree. */
function check(base) {
  const found = differences(join(base, FOLDER), readFileSync(join(base, LIST), "utf8"));
  for (const line of found) console.error(`${FOLDER}/${line}`);
  return found.length === 0;
}

/**
 * The gate against copies of the vendored folder: unchanged it passes, and every change of the
 * file set or of a listed file's bytes is refused.
 */
function selfTest() {
  /** @type {[what: string, change: (folder: string) => void, expected: string[]][]} */
  const cases = [
    ["the unchanged copy", () => {}, []],
    [
      "an added header that shadows a system one",
      (folder) => writeFileSync(join(folder, "include/limits.h"), "#error shadowed\n"),
      ["include/limits.h is not listed"],
    ],
    [
      "a file added elsewhere",
      (folder) => writeFileSync(join(folder, "src/blake2/extra.c"), "\n"),
      ["src/blake2/extra.c is not listed"],
    ],
    [
      "an added link",
      (folder) => symlinkSync("argon2.h", join(folder, "include/stdint.h")),
      ["include/stdint.h is not a plain file"],
    ],
    [
      "a listed file replaced by a link to the same bytes",
      (folder) => {
        cpSync(join(folder, "src/core.h"), join(folder, "core.h.real"));
        unlinkSync(join(folder, "src/core.h"));
        symlinkSync("../core.h.real", join(folder, "src/core.h"));
      },
      ["src/core.h is not a plain file", "core.h.real is not listed"],
    ],
    [
      "a changed file",
      (folder) => writeFileSync(join(folder, "src/core.c"), "/* changed */\n", { flag: "a" }),
      ["src/core.c was changed"],
    ],
    [
      "a deleted file",
      (folder) => unlinkSync(join(folder, "src/thread.h")),
      ["src/thread.h is missing"],
    ],
  ];
  const document = readFileSync(join(root, LIST), "utf8");
  for (const [what, change, expected] of cases) {
    const scratch = mkdtempSync(join(tmpdir(), "mhfe-vendored-argon2-"));
    try {
      const folder = join(scratch, "phc-winner-argon2");
      cpSync(join(root, FOLDER), folder, { recursive: true });
      change(folder);
      const byName = (a, b) => a.localeCompare(b);
      const found = differences(folder, document).sort(byName);
      if (JSON.stringify(found) !== JSON.stringify([...expected].sort(byName))) {
        throw new Error(`self-test: ${what} gives ${JSON.stringify(found)}`);
      }
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  }
  // Each damaged list must be refused for its own reason, not for any error.
  /** @type {[what: string, edit: (text: string) => string, reason: RegExp][]} */
  const damagedLists = [
    [
      "a list without its block",
      (text) => text.replace("```text", "```"),
      /exactly one ```text block/u,
    ],
    ["a path listed twice", (text) => text.replace(/^(.*  LICENSE)$/mu, "$1\n$1"), /listed twice/u],
    [
      "a line of another form",
      (text) => text.replace(/^([0-9a-f]{64}) {2}LICENSE$/mu, "$1 LICENSE"),
      /not a "<SHA-256>  <path>" line/u,
    ],
  ];
  for (const [what, edit, reason] of damagedLists) {
    let refusal = null;
    try {
      listedFiles(edit(document));
    } catch (error) {
      refusal = error.message;
    }
    if (refusal === null) throw new Error(`self-test: ${what} is accepted`);
    if (!reason.test(refusal)) throw new Error(`self-test: ${what} is refused as ${refusal}`);
  }
  console.log(
    `The vendored Argon2 gate refuses every change of its ${cases.length - 1} test cases.`,
  );
}

const args = process.argv.slice(2);
if (args.length === 1 && args[0] === "--self-test") {
  selfTest();
} else if (args.length === 0) {
  if (!check(root)) {
    console.error(`The vendored Argon2 code differs from the list in ${LIST}.`);
    process.exit(1);
  }
  console.log(`${FOLDER} holds exactly the files listed in ${LIST}.`);
} else {
  console.error(USAGE);
  process.exit(2);
}
