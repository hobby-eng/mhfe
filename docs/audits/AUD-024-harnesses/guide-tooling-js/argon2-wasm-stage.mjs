// AUD-024, role guide-tooling-js: does the argon2-wasm stage of packaging/Dockerfile.reproducible
// copy every script that its Node steps need? The stage copies a list of files and then runs
// scripts/build-argon2-wasm.sh, which runs `node scripts/verify-vendored-argon2.mjs` before
// Emscripten and `node scripts/remove-network-code.mjs` after it.
//
// The harness reads the stage's COPY instructions from the Dockerfile, rebuilds the stage's
// /workspace from the working tree in a scratch folder, checks that every relative import of
// every copied script resolves inside it, and runs the vendored-Argon2 gate there as the stage
// does. No Docker, no Emscripten, no network. It writes only into the scratch folder it is given.
//
//   node docs/audits/AUD-024-harnesses/guide-tooling-js/argon2-wasm-stage.mjs <scratch folder>
//
// Exit 0 when every import resolves and the gate runs; exit 1 otherwise.
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

const [scratchArg] = process.argv.slice(2);
if (scratchArg === undefined) {
  console.error("usage: node argon2-wasm-stage.mjs <scratch folder>");
  process.exit(2);
}
const repo = process.cwd();
const dockerfile = readFileSync(join(repo, "packaging/Dockerfile.reproducible"), "utf8");

/** The instructions of the stage named `stage`, continuation lines joined. */
function stageInstructions(text, stage) {
  const joined = text.replace(/\\\n\s*/gu, " ").split("\n");
  const start = joined.findIndex((line) => new RegExp(`^FROM .* AS ${stage}\\b`, "u").test(line));
  if (start < 0) throw new Error(`no stage ${stage}`);
  const rest = joined.slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith("FROM "));
  return (end < 0 ? rest : rest.slice(0, end)).filter((line) => line.trim() !== "");
}

const instructions = stageInstructions(dockerfile, "argon2-wasm");
const workdir = instructions.find((line) => line.startsWith("WORKDIR "))?.split(/\s+/u)[1];
const copies = instructions
  .filter((line) => line.startsWith("COPY ") && !line.includes("--from="))
  .map((line) => line.split(/\s+/u).slice(1));
console.log(`stage argon2-wasm: WORKDIR ${workdir}, ${copies.length} COPY instructions`);

const scratch = resolve(scratchArg, "argon2-wasm-stage");
rmSync(scratch, { recursive: true, force: true });
mkdirSync(scratch, { recursive: true });
const copied = [];
for (const args of copies) {
  const destination = args.at(-1);
  const sources = args.slice(0, -1);
  for (const source of sources) {
    const into = destination.endsWith("/")
      ? join(scratch, destination, basename(source))
      : join(scratch, destination);
    mkdirSync(dirname(into), { recursive: true });
    cpSync(join(repo, source), into, { recursive: true });
    copied.push(statSync(join(repo, source)).isDirectory() ? `${source}/` : source);
  }
}
console.log(`copied into the stage: ${copied.join(", ")}`);

let failed = false;
// Every relative import of every copied script must resolve inside the stage.
for (const script of copied.filter((path) => path.endsWith(".mjs"))) {
  const at = join(scratch, "scripts", basename(script));
  const text = readFileSync(at, "utf8");
  for (const [, specifier] of text.matchAll(/^import[^"']*["'](\.{1,2}\/[^"']+)["']/gmu)) {
    const target = resolve(dirname(at), specifier);
    const present = existsSync(target);
    console.log(`${present ? "ok  " : "FAIL"} ${script} imports ${specifier}`);
    if (!present) failed = true;
  }
}
// The gate, run in the stage's workspace as scripts/build-argon2-wasm.sh runs it there.
const gate = spawnSync(process.execPath, ["scripts/verify-vendored-argon2.mjs"], {
  cwd: scratch,
  encoding: "utf8",
});
const firstLine = `${gate.stdout}${gate.stderr}`.split("\n").find((line) => line.trim() !== "");
console.log(
  `${gate.status === 0 ? "ok  " : "FAIL"} node scripts/verify-vendored-argon2.mjs in the stage: ` +
    `exit ${gate.status}: ${firstLine?.replaceAll(scratch, "<stage>")}`,
);
if (gate.status !== 0) {
  failed = true;
  const detail = `${gate.stderr}`.split("\n").filter((line) => /Cannot find/u.test(line));
  for (const line of detail) console.log(`     ${line.trim().replaceAll(scratch, "<stage>")}`);
  // Control: the same stage with the missing imports added from the working tree passes, so the
  // missing files are the only cause.
  for (const script of copied.filter((path) => path.endsWith(".mjs"))) {
    const at = join(scratch, "scripts", basename(script));
    for (const [, specifier] of readFileSync(at, "utf8").matchAll(
      /^import[^"']*["'](\.{1,2}\/[^"']+)["']/gmu,
    )) {
      const target = resolve(dirname(at), specifier);
      if (!existsSync(target)) cpSync(join(repo, "scripts", specifier), target);
    }
  }
  const control = spawnSync(process.execPath, ["scripts/verify-vendored-argon2.mjs"], {
    cwd: scratch,
    encoding: "utf8",
  });
  console.log(
    `control: with the missing imports added, the gate exits ${control.status}: ` +
      `${control.stdout.trim()}`,
  );
}
console.log(failed ? "The argon2-wasm stage lacks a script its steps need." : "The stage is complete.");
process.exit(failed ? 1 : 0);
