// The command line of a gate script: no argument checks the repository, --self-test runs the
// gate's controls, named modes run other checks, and anything else is refused with exit code 2. Used by
// scripts/verify-code-rules.mjs, scripts/verify-pinned-versions.mjs,
// scripts/verify-vendored-argon2.mjs and scripts/verify-docker-stages.mjs.

import { parseArgs } from "node:util";

/**
 * A check, build or generator's strict arguments, before it reads or writes anything. `options`
 * uses node:util's option descriptors; `operands` is the exact number of positional arguments.
 * A refused command line prints the usage and exits 2, as a gate does.
 */
export function scriptArguments(usage, { options = {}, operands = 0 } = {}) {
  try {
    const parsed = parseArgs({ options, allowPositionals: operands > 0, strict: true });
    if (
      parsed.positionals.length !== operands ||
      parsed.positionals.some((value) => value === "")
    ) {
      throw new Error("Wrong number of operands or an empty operand.");
    }
    return parsed;
  } catch {
    console.error(usage);
    process.exit(2);
  }
}

/**
 * Runs a gate from its command line: `check` returns whether the repository passes and has said
 * why; a failed check ends with exit code 1. An optional `operand` handles one non-option
 * argument; a gate without `check` refuses an empty command line.
 */
export function runGate(usage, { check, selfTest, modes = {}, operand }) {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--self-test") {
    selfTest();
  } else if (args.length === 0 && check !== undefined) {
    if (!check()) process.exit(1);
  } else if (args.length === 1 && Object.hasOwn(modes, args[0])) {
    if (!modes[args[0]]()) process.exit(1);
  } else if (args.length === 1 && !args[0].startsWith("-") && operand !== undefined) {
    if (!operand(args[0])) process.exit(1);
  } else {
    console.error(usage);
    process.exit(2);
  }
}

/**
 * Prints a gate's findings, one a line, then `failed` with their number, or `passed` when there
 * are none; returns whether there were none.
 */
export function reported(found, failed, passed) {
  for (const line of found) console.error(line);
  if (found.length > 0) {
    console.error(failed(found.length));
    return false;
  }
  console.log(passed);
  return true;
}
