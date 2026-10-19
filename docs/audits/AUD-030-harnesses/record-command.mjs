/** Records bounded AUD-030 commands in local-only evidence without copying the checkout. */
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";

const EVIDENCE = "docs/audits/AUD-030-evidence";
const RESERVE_KIB = 3 * 1024 * 1024;
const BUDGET_KIB = 2 * 1024 * 1024;
const SAMPLE_MS = 1000;
const TIMEOUT_MS = 30 * 60 * 1000;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function git(...args) {
  const result = spawnSync("git", args, { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")}: ${result.stderr}`);
  return result.stdout;
}

function sourceMap() {
  const names = git("ls-files", "--cached", "--others", "--exclude-standard", "-z");
  return Object.fromEntries(
    [...new Set(names.split("\0").filter(Boolean))]
      .filter((name) => !name.startsWith("docs/audits/") && existsSync(name))
      .sort()
      .map((name) => [name, sha256(readFileSync(name))]),
  );
}

function memory(pid) {
  const available = /^MemAvailable:\s+(\d+)/m.exec(readFileSync("/proc/meminfo", "utf8"));
  if (!available) throw new Error("MemAvailable is unavailable");
  const processes = new Map();
  for (const entry of readdirSync("/proc").filter((name) => /^\d+$/.test(name))) {
    let status;
    try {
      status = readFileSync(`/proc/${entry}/status`, "utf8");
    } catch (error) {
      // A process can exit between enumeration and inspection.
      if (error.code === "ENOENT" || error.code === "ESRCH") continue;
      throw error;
    }
    processes.set(Number(entry), {
      parent: Number(/^PPid:\s+(\d+)/m.exec(status)?.[1]),
      rss: Number(/^VmRSS:\s+(\d+)/m.exec(status)?.[1] ?? 0),
    });
  }
  const descendants = new Set([pid]);
  let previous;
  do {
    previous = descendants.size;
    for (const [child, info] of processes) {
      if (descendants.has(info.parent)) descendants.add(child);
    }
  } while (previous !== descendants.size);
  return {
    availableKiB: Number(available[1]),
    descendantRssKiB: [...descendants].reduce(
      (sum, child) => sum + (processes.get(child)?.rss ?? 0),
      0,
    ),
  };
}

async function main() {
  const [name, ...argv] = process.argv.slice(2);
  if (!name || !/^[a-z0-9-]+$/.test(name) || argv.length === 0) {
    throw new Error("Usage: node record-command.mjs <unique-name> <command> [arguments...]");
  }
  mkdirSync(EVIDENCE, { recursive: true });
  const stem = resolve(EVIDENCE, name);
  if (existsSync(`${stem}.command.json`) || existsSync(`${stem}.log`)) {
    throw new Error("Refusing to overwrite retained command evidence");
  }
  const initial = memory(process.pid);
  if (initial.availableKiB < RESERVE_KIB + BUDGET_KIB) {
    throw new Error(
      "Insufficient available memory for the 2 GiB command budget plus 3 GiB reserve",
    );
  }
  const before = sourceMap();
  const startedUtc = new Date().toISOString();
  const log = openSync(`${stem}.log`, "wx");
  const environment = {
    CARGO_HOME: process.env.CARGO_HOME,
    RUSTUP_HOME: process.env.RUSTUP_HOME,
    CARGO_BUILD_JOBS: "1",
    RUST_TEST_THREADS: "1",
    EMCC_CORES: "1",
    NODE_OPTIONS: "--max-old-space-size=768",
    TZ: "UTC",
  };
  const child = spawn(argv[0], argv.slice(1), {
    detached: true,
    env: { ...process.env, ...environment },
    stdio: ["ignore", log, log],
  });
  let stoppedReason = null;
  let monitorError = null;
  let peakRssKiB = 0;
  let minimumAvailableKiB = initial.availableKiB;
  const stop = (reason) => {
    if (stoppedReason !== null) return;
    stoppedReason = reason;
    if (child.pid !== undefined) {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch (error) {
        if (error.code !== "ESRCH") monitorError = String(error);
      }
    }
  };
  const monitor = setInterval(() => {
    try {
      const sample = memory(child.pid);
      peakRssKiB = Math.max(peakRssKiB, sample.descendantRssKiB);
      minimumAvailableKiB = Math.min(minimumAvailableKiB, sample.availableKiB);
      if (sample.availableKiB < RESERVE_KIB) stop("available-memory-reserve");
      if (sample.descendantRssKiB > BUDGET_KIB) stop("descendant-rss-budget");
    } catch (error) {
      monitorError = String(error);
      stop("memory-monitor-error");
    }
  }, SAMPLE_MS);
  const deadline = setTimeout(() => stop("timeout"), TIMEOUT_MS);
  let spawnError = null;
  const result = await new Promise((done) => {
    child.once("error", (error) => {
      spawnError = String(error);
    });
    child.once("close", (exitCode, signal) => done({ exitCode, signal }));
  });
  clearInterval(monitor);
  clearTimeout(deadline);
  closeSync(log);
  const after = sourceMap();
  const record = {
    argv,
    environment,
    startedUtc,
    completedUtc: new Date().toISOString(),
    ...result,
    stoppedReason,
    spawnError,
    monitorError,
    sourceBefore: before,
    sourceAfter: after,
    sourceUnchanged: JSON.stringify(before) === JSON.stringify(after),
    logSha256: sha256(readFileSync(`${stem}.log`)),
    memory: { reserveKiB: RESERVE_KIB, budgetKiB: BUDGET_KIB, peakRssKiB, minimumAvailableKiB },
    limits: "One-second conservative descendant RSS samples, not exact allocation peaks.",
  };
  writeFileSync(`${stem}.command.json`, `${JSON.stringify(record, null, 2)}\n`, { flag: "wx" });
  console.log(JSON.stringify({ name, ...result, stoppedReason, spawnError, monitorError }));
  process.exitCode =
    result.exitCode === 0 && stoppedReason === null && spawnError === null && monitorError === null
      ? 0
      : 1;
}

await main();
