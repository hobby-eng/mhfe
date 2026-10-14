// The command line of a gate script: no argument checks the repository, --self-test runs the
// gate's controls, and anything else is refused with the usage and exit code 2. Used by
// scripts/verify-code-rules.mjs, scripts/verify-pinned-versions.mjs and
// scripts/verify-vendored-argon2.mjs.

/**
 * Runs a gate from its command line: `check` returns whether the repository passes and has said
 * why; a failed check ends with exit code 1.
 */
export function runGate(usage, { check, selfTest }) {
  const args = process.argv.slice(2);
  if (args.length === 1 && args[0] === "--self-test") {
    selfTest();
  } else if (args.length === 0) {
    if (!check()) process.exit(1);
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
