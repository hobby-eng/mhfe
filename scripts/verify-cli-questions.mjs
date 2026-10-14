// CORE-41: every CLI choice call has an inventoried answer family, with command options or a
// reason it is an interactive follow-up. Rust unit tests bind the table to the actual clap tree.
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { reported, runGate } from "./gate-command-line.mjs";
import { rustRunTimeLines } from "./rust-code.mjs";

const directory = fileURLToPath(new URL("../src/bin/mhfe", import.meta.url));
const inventory = JSON.parse(readFileSync(new URL("cli-questions.json", import.meta.url), "utf8"));
const USAGE = "usage: node scripts/verify-cli-questions.mjs [--self-test]";
const CHOICE =
  /(?:\.\s*|\bchoice\s*::\s*)(choose(?:_here)?(?:_without_default)?)\s*\(|\b(?:check::)?(ask_passphrase|ask_number)\s*\(/gu;

/** Source files below a directory; new modules are read as well. */
function files(folder, prefix = "") {
  return readdirSync(folder, { withFileTypes: true }).flatMap((entry) => {
    const path = join(prefix, entry.name);
    if (entry.isDirectory()) return files(join(folder, entry.name), path);
    return entry.name.endsWith(".rs") ? [path] : [];
  });
}

/** Actual call-site counts, excluding Rust comments, literals, tests and declarations. */
function callSites(sources) {
  const found = new Map();
  for (const [path, source] of sources) {
    const code = rustRunTimeLines(source.split("\n"))
      .map(([, line]) => line)
      .join("\n");
    const declarations = [...code.matchAll(/\bfn\s+(\w+)/gu)];
    const currentAt = (index) => declarations.findLast((match) => match.index < index)?.[1] ?? "";
    for (const match of code.matchAll(CHOICE)) {
      if (/\bfn\s*$/u.test(code.slice(0, match.index))) continue;
      const method = match[1] ?? match[2];
      const site = `${path}:${currentAt(match.index)}:${method}`;
      found.set(site, (found.get(site) ?? 0) + 1);
    }
    // A numeric follow-up has one text prompt instead of a choice list.
    if (path === "container_search.rs") {
      for (const match of code.matchAll(/\.\s*visible\s*\(/gu)) {
        if (currentAt(match.index) !== "read_own_gap") continue;
        const site = `${path}:read_own_gap:visible`;
        found.set(site, (found.get(site) ?? 0) + 1);
      }
    }
  }
  return found;
}

/** Table completeness and a two-way match to the code; an empty inventory never passes. */
function findings(table, sources) {
  const found = [];
  const actual = callSites(sources);
  const listed = new Set();
  for (const row of table.sites) {
    if (listed.has(row.site)) found.push(`CORE-41 repeated question ${row.site}`);
    listed.add(row.site);
    if (actual.get(row.site) !== row.occurrences || !(row.occurrences > 0)) {
      found.push(
        `CORE-41 ${row.site}: ${actual.get(row.site) ?? 0} calls, ${row.occurrences} listed`,
      );
    }
    if (row.answers.length === 0) found.push(`CORE-41 ${row.site}: no answer families`);
    for (const answer of row.answers) {
      const binding = table.bindings[answer.binding];
      const option =
        Array.isArray(binding) &&
        binding.length > 0 &&
        binding.every((entry) => entry.commands.length > 0 && entry.options.length > 0);
      const followUp = typeof answer.followUp === "string" && answer.followUp.trim().length > 0;
      if (!answer.meaning || option === followUp) {
        found.push(
          `CORE-41 ${row.site}: ${answer.meaning ?? "unnamed answer"} needs options or a follow-up reason`,
        );
      }
    }
  }
  for (const site of actual.keys()) {
    if (!listed.has(site)) found.push(`CORE-41 unlisted question ${site}`);
  }
  if (actual.size === 0) found.push("CORE-41 no question call sites were read");
  return found;
}

/** A new call, an unmapped answer, a lost site and a fake empty coverage must all fail. */
function selfTest() {
  const sources = new Map([["case.rs", "fn ask() { input.choose(&q, &a)?; }\n"]]);
  const valid = {
    bindings: { mapped: [{ commands: ["command"], options: ["answer"] }] },
    sites: [
      {
        site: "case.rs:ask:choose",
        occurrences: 1,
        answers: [{ meaning: "Answer", binding: "mapped" }],
      },
    ],
  };
  if (findings(valid, sources).length !== 0) throw new Error("mapped control is refused");
  const controls = [
    [
      valid,
      new Map([
        ["case.rs", sources.get("case.rs") + "fn added() { input.choose_here(&q, &a)?; }\n"],
      ]),
    ],
    [valid, new Map()],
    [{ ...valid, sites: [] }, sources],
    [{ ...valid, bindings: {} }, sources],
    [{ ...valid, sites: [{ ...valid.sites[0], answers: [] }] }, sources],
  ];
  for (const [table, code] of controls) {
    if (findings(table, code).length === 0) throw new Error("an inventory mutation passed");
  }
  const followUp = structuredClone(valid);
  followUp.sites[0].answers = [{ meaning: "Review", followUp: "The result must be seen first." }];
  if (findings(followUp, sources).length !== 0) throw new Error("follow-up control is refused");
  followUp.sites[0].answers[0].followUp = " ";
  if (findings(followUp, sources).length === 0) throw new Error("an empty reason passed");
  console.log("The CLI inventory catches all six incomplete-coverage controls.");
}

runGate(USAGE, {
  selfTest,
  check: () =>
    reported(
      findings(
        inventory,
        new Map(
          files(directory).map((path) => [path, readFileSync(join(directory, path), "utf8")]),
        ),
      ),
      (count) => `${count} incomplete CLI question mappings.`,
      `Every CLI question call is listed in ${inventory.sites.length} scoped mappings; clap option existence is checked by cargo test.`,
    ),
});
