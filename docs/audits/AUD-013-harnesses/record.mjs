import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const directory = "docs/audits/AUD-013-evidence";
mkdirSync(directory, { recursive: true });
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const [label, command, ...args] = process.argv.slice(2);
if (!label || !command || !/^[a-z0-9-]+$/.test(label)) {
  throw new Error("Supply an evidence label and a command, or snapshot.");
}
if (command === "snapshot") {
  const git = (...argv) => execFileSync("git", argv, { encoding: "utf8" });
  const paths = [...new Set(git("ls-files", "-c", "-o", "--exclude-standard", "-z")
    .split("\0").filter((p) => p && !p.startsWith("docs/audits/")))].sort();
  const records = paths.map((p) => [p, existsSync(p) ? hash(readFileSync(p)) : "deleted"]);
  const artifacts = ["target/debug/mhfe", "target/release/mhfe", "dist/runtime/mhfe.wasm",
    "dist/modules.json"].filter(existsSync).map((p) => [p, hash(readFileSync(p))]);
  const procedures = ["docs/FULL_AUDIT_GUIDE.md", "docs/audits/AUDIT_STANDARD.md",
    "docs/audits/AUDIT_TEMPLATE.md", "docs/audit-report.schema.json"];
  const procedureHashes = Object.fromEntries(procedures.map((p) =>
    ["multi-chain-wallet-tools/" + p, hash(readFileSync("../multi-chain-wallet-tools/" + p))]));
  const result = { capturedAt: new Date().toISOString(), head: git("rev-parse", "HEAD").trim(),
    branch: git("branch", "--show-current").trim(), status: git("status", "--short"),
    sourceFingerprint: hash(JSON.stringify(records)), records, artifacts, procedureHashes };
  writeFileSync(`${directory}/${label}.json`, JSON.stringify(result, null, 2) + "\n");
  console.log(JSON.stringify({ ...result, records: `${records.length} paths` }, null, 2));
} else {
  const startedAt = new Date().toISOString();
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const output = (result.stdout ?? "") + (result.stderr ?? "");
  writeFileSync(`${directory}/${label}.log`, output);
  const metadata = { command: [command, ...args], cwd: process.cwd(), startedAt,
    endedAt: new Date().toISOString(), exitCode: result.status, signal: result.signal,
    failure: result.error?.message ?? null, logSha256: hash(output),
    toolchainEnvironment: { CARGO_HOME: process.env.CARGO_HOME ?? null,
      RUSTUP_HOME: process.env.RUSTUP_HOME ?? null } };
  writeFileSync(`${directory}/${label}.command.json`, JSON.stringify(metadata, null, 2) + "\n");
  process.stdout.write(output);
  console.log(JSON.stringify(metadata));
  process.exitCode = result.status ?? 1;
}
