// A real fast-mode launcher under test: startup, bounded diagnostics and process cleanup.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const START_DEADLINE_MS = 20_000;
const STOP_DEADLINE_MS = 5_000;
const DIAGNOSTIC_CHARACTERS = 64 * 1024;
const SERVE_SOURCE = new URL("../../src/bin/mhfe/serve.rs", import.meta.url);
const source = readFileSync(SERVE_SOURCE, "utf8");
// Values come from the native launcher's source; this adds no third copy of its policy.
const checksumName = /const CHECKSUM_FILE: &str = "([^"]+)"/u.exec(source)?.[1];
const headerBlock = /const SECURITY_HEADERS:[\s\S]*?= \[([\s\S]*?)\];/u.exec(source)?.[1];
if (!checksumName || !headerBlock)
  throw new Error("The fast-mode launcher constants were not found.");
const headers = [...headerBlock.matchAll(/\(("[^"]+"), ("[^"]+")\)/gu)].map((match) =>
  JSON.parse(`[${match[1]}, ${match[2]}]`),
);
// Deliberate copy: the public fast-mode response contract has seven security headers. Browser
// isolation and startup checks also reject a policy weakened in both launcher implementations.
assert.equal(headers.length, 7, "the complete fast-mode security policy is read");

/** Writes the checksum the real launcher requires for this exact generated page. */
export function writeLauncherChecksum(pagePath) {
  const digest = createHash("sha256").update(readFileSync(pagePath)).digest("hex");
  writeFileSync(join(dirname(pagePath), checksumName), `${digest}  ${basename(pagePath)}\n`);
}

/** A browser response carries the launcher's full policy, including the three isolation headers. */
export async function checkLauncherResponse(response) {
  assert.equal(response?.status(), 200, "the real launcher serves the checked HTML page");
  const actual = await response.allHeaders();
  for (const [name, value] of headers) {
    assert.equal(actual[name.toLowerCase()], value, `the launcher sends ${name}`);
  }
}

/** Owns the child until stop(), including when startup fails before a URL is printed. */
export class FastModeLauncher {
  #child;
  #closed;
  #output = "";
  #address;

  get address() {
    return this.#address;
  }

  /** Starts the native or Python launcher, without opening any browser itself. */
  static async start(kind, pagePath, nativePath) {
    if (!["native", "python"].includes(kind)) throw new Error(`Unknown launcher: ${kind}`);
    const launcher = new FastModeLauncher();
    try {
      await launcher.#start(kind, pagePath, nativePath);
      return launcher;
    } catch (error) {
      await launcher.stop();
      throw error;
    }
  }

  async #start(kind, pagePath, nativePath) {
    const python = new URL("../../packaging/mhfe-fast-mode.py", import.meta.url);
    const [command, args] =
      kind === "native"
        ? [nativePath, ["serve", "--no-browser", pagePath]]
        : ["python3", [fileURLToPath(python), "--no-browser", pagePath]];
    this.#child = spawn(command, args, {
      env: { ...process.env, NO_COLOR: "1", PYTHONUNBUFFERED: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    this.#closed = new Promise((resolve) => {
      this.#child.once("close", (code, signal) => resolve({ code, signal }));
    });
    await new Promise((resolve, reject) => {
      const deadline = setTimeout(
        () => reject(new Error(`No address from the ${kind} launcher: ${this.#output}`)),
        START_DEADLINE_MS,
      );
      const read = (chunk) => {
        this.#output = (this.#output + chunk).slice(-DIAGNOSTIC_CHARACTERS);
        const address = /http:\/\/127\.0\.0\.1:\d+\//u.exec(this.#output)?.[0];
        if (address) {
          this.#address = address;
          clearTimeout(deadline);
          resolve();
        }
      };
      this.#child.stdout.on("data", read);
      this.#child.stderr.on("data", read);
      this.#child.once("error", (error) => {
        clearTimeout(deadline);
        reject(error);
      });
      this.#closed.then(() => {
        clearTimeout(deadline);
        reject(new Error(`The ${kind} launcher ended: ${this.#output}`));
      });
    });
  }

  /** Stops and reaps the launcher, including a child that ignores the first signal. */
  async stop() {
    if (!this.#child || this.#child.exitCode !== null || this.#child.signalCode !== null) return;
    this.#child.kill("SIGTERM");
    if (await this.#waitClosed()) return;
    this.#child.kill("SIGKILL");
    if (!(await this.#waitClosed())) throw new Error(`The launcher did not stop: ${this.#output}`);
  }

  async #waitClosed() {
    let timer;
    const expired = new Promise((resolve) => {
      timer = setTimeout(() => resolve(false), STOP_DEADLINE_MS);
    });
    try {
      return await Promise.race([this.#closed.then(() => true), expired]);
    } finally {
      clearTimeout(timer);
    }
  }
}
