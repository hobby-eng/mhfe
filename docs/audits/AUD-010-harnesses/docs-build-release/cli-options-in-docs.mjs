// AUD-010 probe (docs-build-release): every command-line option the documents name exists in the
// program's own help. It runs `mhfe <command> --help` (which runs no self-test and reads no
// secret) for every command the overview lists, then reads the documents. Exits 1 when a document
// names an option that no command has, or that the command it is written with does not have.
//
//   node docs/audits/AUD-010-harnesses/docs-build-release/cli-options-in-docs.mjs [path/to/mhfe]
//
// Default program: target/release/mhfe. Options of other programs (cargo, npm, gpg, sha256sum,
// pip, gh, git, docker, tar) are skipped by their command word.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const program = process.argv[2] ?? "target/release/mhfe";
const DOCUMENTS = [
  "README.md",
  "SECURITY.md",
  "docs/API.md",
  "docs/BROWSER-PACKAGE.md",
  "docs/RELEASING.md",
  "docs/releases/v0.5.0.md",
];
const OTHER_PROGRAMS =
  /\b(cargo|npm|npx|gpg|sha256sum|pip|python3?|gh|git|docker|tar|rustup|wasm-bindgen|node|curl|zip|scripts\/[\w.-]+)\b/u;
// Options the documents name in prose for another program, reviewed by hand in AUD-010.
const OPTIONS_OF_OTHER_PROGRAMS = new Map([
  ["--keyname", "systemd-ask-password (README, For scripts)"],
  ["--accept-cached", "systemd-ask-password (README, For scripts)"],
  ["--check", "scripts/generate-published-rounds.py"],
  ["--ignore-missing", "sha256sum (docs/RELEASING.md)"],
]);
const help = (args) =>
  execFileSync(program, [...args, "--help"], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });

const overview = help([]);
// The commands are the entries of the "Commands:" section, up to the next section.
const commandSection = /^Commands:\n([\s\S]*?)\n\n/mu.exec(overview)[1];
const commands = [...commandSection.matchAll(/^ {2}([a-z][a-z-]+) {2,}/gmu)]
  .map((match) => match[1])
  .filter((name) => name !== "help");
const optionsOf = new Map();
for (const command of commands) {
  const text = help([command]);
  optionsOf.set(command, new Set([...text.matchAll(/--[a-z][a-z0-9-]*/gu)].map((m) => m[0])));
}
const everyOption = new Set([...optionsOf.values()].flatMap((set) => [...set]));
for (const generic of ["--help", "--version"]) everyOption.add(generic);

const problems = [];
let checked = 0;
for (const path of DOCUMENTS) {
  const lines = readFileSync(path, "utf8").split("\n");
  for (const [index, line] of lines.entries()) {
    // Each code span, or the whole line inside a fenced block, is read on its own.
    const spans = [...line.matchAll(/`([^`]+)`/gu)].map((match) => match[1]);
    if (spans.length === 0 && /^\s*mhfe\s/u.test(line)) spans.push(line);
    for (const span of spans) {
      if (OTHER_PROGRAMS.test(span)) continue;
      const options = [...span.matchAll(/(?<![\w-])--[a-z][a-z0-9-]*/gu)].map((m) => m[0]);
      if (options.length === 0) continue;
      const command = /\bmhfe\s+([a-z][a-z-]+)/u.exec(span)?.[1];
      for (const option of options) {
        checked += 1;
        if (OPTIONS_OF_OTHER_PROGRAMS.has(option)) continue;
        const known = command && optionsOf.has(command) ? optionsOf.get(command) : everyOption;
        if (!known.has(option)) {
          problems.push(
            `${path}:${index + 1}: ${option}${command ? ` of mhfe ${command}` : ""} is not in the help`,
          );
        }
      }
    }
  }
}
console.log(`Commands: ${commands.join(", ")}.`);
console.log(`Checked ${checked} option mentions in ${DOCUMENTS.length} documents.`);
for (const problem of problems) console.log(`FAIL ${problem}`);
if (problems.length > 0) process.exit(1);
console.log("PASS: every option named in the documents exists.");
