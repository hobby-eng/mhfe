// Prepare the real launcher routes without opening a browser or running full-size vectors.
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const { FastModeLauncher, checkLauncherResponse, writeLauncherChecksum } = await import(
  pathToFileURL(resolve("scripts/browser-check/fast-mode-launcher.mjs")).href
);
const native = resolve("target/release/mhfe");
const folder = resolve("../tmp/aud024/launcher-process-controls");
mkdirSync(folder, { recursive: true });
const page = resolve(folder, "public.html");
const html = "<!doctype html><title>public launcher control</title><p>public synthetic data</p>";
writeFileSync(page, html);
writeLauncherChecksum(page);
for (const kind of ["native", "python"]) {
  const launcher = await FastModeLauncher.start(kind, page, native);
  try {
    const response = await fetch(launcher.address, { signal: AbortSignal.timeout(5000) });
    await checkLauncherResponse({
      status: () => response.status,
      allHeaders: async () => Object.fromEntries(response.headers),
    });
    assert.equal(await response.text(), html);
    console.log(kind, "serves the exact checked page with all seven policy headers");
  } finally {
    await launcher.stop();
  }
}
writeFileSync(page, html + "changed");
for (const kind of ["native", "python"]) {
  await assert.rejects(FastModeLauncher.start(kind, page, native), /The .* launcher ended/u);
}
await assert.rejects(FastModeLauncher.start("unknown", page), /Unknown launcher/u);
console.log(
  "Both reject changed content; startup failures reap their child; no browsers executed.",
);
