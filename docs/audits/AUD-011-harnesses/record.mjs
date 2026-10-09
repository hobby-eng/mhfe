// Run from the repository root. Capture read-only audit commands and exact source bytes.
import { spawnSync, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const directory = "docs/audits/AUD-011-evidence";
mkdirSync(directory, { recursive: true });
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const [label, command, ...args] = process.argv.slice(2);
if (command === "snapshot") {
  const git = (...argv) => execFileSync("git", argv, { encoding: "utf8" });
  const paths = [...new Set(git("ls-files", "-c", "-o", "--exclude-standard", "-z")
    .split("\0").filter((p) => p && !p.startsWith("docs/audits/")))].sort();
  const records = paths.map((p) => [p, existsSync(p) ? hash(readFileSync(p)) : "deleted"]);
  const artifacts = ["target/debug/mhfe", "target/release/mhfe", "dist/runtime/mhfe.wasm",
    "dist/modules.json"].filter(existsSync).map((p) => [p, hash(readFileSync(p))]);
  const procedureFiles = ["docs/FULL_AUDIT_GUIDE.md", "docs/audits/AUDIT_STANDARD.md",
    "docs/audits/AUDIT_TEMPLATE.md", "docs/audit-report.schema.json"];
  const procedureHashes = Object.fromEntries(procedureFiles.map((p) =>
    ["multi-chain-wallet-tools/" + p, hash(readFileSync("../multi-chain-wallet-tools/" + p))]));
  const record = { capturedAt: new Date().toISOString(), head: git("rev-parse", "HEAD").trim(),
    status: git("status", "--short"), sourceFingerprint: hash(JSON.stringify(records)),
    records, artifacts, procedureHashes };
  writeFileSync(`${directory}/${label}.json`, JSON.stringify(record, null, 2) + "\n");
  console.log(JSON.stringify({ label, head: record.head, fingerprint: record.sourceFingerprint,
    paths: records.length, artifacts, procedureHashes }, null, 2));
} else {
  const startedAt = new Date().toISOString();
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  const output = (result.stdout ?? "") + (result.stderr ?? "");
  writeFileSync(`${directory}/${label}.log`, output);
  const record = { command: [command, ...args], cwd: process.cwd(), startedAt,
    endedAt: new Date().toISOString(), exitCode: result.status, signal: result.signal,
    failure: result.error?.message ?? null, logSha256: hash(output) };
  writeFileSync(`${directory}/${label}.command.json`, JSON.stringify(record, null, 2) + "\n");
  process.stdout.write(output);
  console.log(JSON.stringify(record));
  process.exitCode = result.status ?? 1;
}
