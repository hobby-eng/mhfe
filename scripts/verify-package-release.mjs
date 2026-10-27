// Checks that scripts/package-release.sh refuses an unknown or repeated package with the usage and
// exit code 2 before it builds or writes anything, so that no archive is left without its licence
// check and SHA256SUMS. As a control, a legal command line must get past that check: with
// RUSTFLAGS set, which packaging/remap-builder-paths.sh refuses before any build, it creates the
// output folder and stops there.
//
//   node scripts/verify-package-release.mjs
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("package-release.sh", import.meta.url));
/** The output folder of the command lines below, in a fresh temporary folder for each run. */
const OUTPUT = "<output>";
const REFUSED = [
  ["v0.0.0", OUTPUT, "browser", "no-such-package"],
  ["v0.0.0", OUTPUT, "browser", "linux-x86_64", "browser"],
];

/** Runs the script with `args` and `environment`; tells its exit code and whether OUTPUT exists. */
function run(args, environment) {
  const base = mkdtempSync(join(tmpdir(), "mhfe-package-release-"));
  try {
    const output = join(base, "out");
    const result = spawnSync(
      "bash",
      [SCRIPT, ...args.map((arg) => (arg === OUTPUT ? output : arg))],
      {
        encoding: "utf8",
        env: { ...process.env, ...environment },
      },
    );
    return { status: result.status, stderr: result.stderr, created: existsSync(output) };
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
}

const failures = [];
for (const args of REFUSED) {
  const { status, stderr, created } = run(args, {});
  if (status !== 2 || !stderr.includes("usage: ") || created) {
    failures.push(`${args.join(" ")}: exit ${status}, output created: ${created}\n${stderr}`);
  }
}
const legal = run(["v0.0.0", OUTPUT, "browser", "linux-x86_64"], { RUSTFLAGS: "-C debuginfo=0" });
if (!legal.created || !legal.stderr.includes("RUSTFLAGS")) {
  failures.push(
    `a legal command line did not get past the check: exit ${legal.status}\n${legal.stderr}`,
  );
}
if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}
console.log(`package-release.sh refuses ${REFUSED.length} wrong package lists before any output.`);
