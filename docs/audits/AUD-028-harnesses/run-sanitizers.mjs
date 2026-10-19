// AUD-028: serial instrumented C checks; original sources stay in this checkout.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const harness = fileURLToPath(new URL(".", import.meta.url));
const compiler = "/usr/lib/llvm-21/bin/clang";
const environment = {
  ...process.env,
  ASAN_OPTIONS: "detect_leaks=1:halt_on_error=1:symbolize=1",
  ASAN_SYMBOLIZER_PATH: "/usr/lib/llvm-21/bin/llvm-symbolizer",
  UBSAN_OPTIONS: "halt_on_error=1:print_stacktrace=1",
};
const flags = [
  "-std=c11",
  "-D_DEFAULT_SOURCE",
  "-O1",
  "-g",
  "-fno-omit-frame-pointer",
  "-fno-optimize-sibling-calls",
  "-fno-common",
  "-fsanitize=address,undefined",
  "-fno-sanitize-recover=all",
  "-pthread",
  "-Ivendor/phc-winner-argon2/include",
  "-Ivendor/phc-winner-argon2/src",
];
const sources = ["argon2.c", "core.c", "encoding.c", "thread.c", "blake2/blake2b.c"].map(
  (path) => `vendor/phc-winner-argon2/src/${path}`,
);
const records = [];
const sha = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

function unchanged(paths, expected) {
  assert.deepEqual(Object.fromEntries(paths.map((path) => [path, sha(path)])), expected);
}

function run(executable, argv, expected = 0, diagnostic) {
  const startedUtc = new Date().toISOString();
  console.log(JSON.stringify({ executable, argv, startedUtc }));
  const result = spawnSync(executable, argv, {
    env: environment,
    timeout: 120_000,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  process.stdout.write(result.stdout ?? "");
  process.stdout.write(result.stderr ?? "");
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  if (expected === "nonzero") assert(result.status !== null && result.status !== 0);
  else assert.equal(result.status, expected);
  if (diagnostic) assert.match(result.stderr, diagnostic);
  records.push({
    executable,
    argv,
    startedUtc,
    endedUtc: new Date().toISOString(),
    exitCode: result.status,
    expectedExit: expected,
    expectedDiagnostic: diagnostic?.source ?? null,
  });
}

function main() {
  assert.equal(process.argv.length, 3, "one output directory operand required");
  const output = resolve(process.argv[2]);
  mkdirSync(output, { recursive: true });
  const paths = [
    ...readdirSync("vendor/phc-winner-argon2", { recursive: true })
      .filter((path) => /\.[ch]$/u.test(path))
      .map((path) => `vendor/phc-winner-argon2/${path}`),
    "src/engine/argon2_ref.c",
    "src/engine/argon2_simd.c",
    "src/engine/argon2_stack.h",
    resolve(harness, "argon2-sanitized.c"),
    resolve(harness, "sanitizer-tripwire.c"),
    fileURLToPath(import.meta.url),
  ];
  const before = Object.fromEntries(paths.map((path) => [path, sha(path)]));
  for (const path of [
    "vendor/phc-winner-argon2/src/ref.c",
    "vendor/phc-winner-argon2/include/argon2.h",
    "vendor/phc-winner-argon2/src/core.h",
  ]) {
    assert(Object.hasOwn(before, path), "transitive C source/header must be bound");
    assert.throws(() => unchanged(paths, { ...before, [path]: "0".repeat(64) }));
  }
  unchanged(paths, before);
  console.log("PASS: three independent source/header digest refusal controls");
  run(compiler, ["--version"]);
  const objects = sources.map((path, index) => {
    const object = resolve(output, `common-${index}.o`);
    run(compiler, [...flags, "-c", path, "-o", object]);
    return object;
  });
  const probe = resolve(harness, "argon2-sanitized.c");
  const portable = resolve(output, "argon2-portable");
  run(compiler, [...flags, probe, ...objects, "src/engine/argon2_ref.c", "-o", portable]);
  run(portable, []);
  run(portable, ["--wrong-expected"], 2, /tag mismatch/);
  if (process.arch === "x64") {
    const optimized = ["sse2", "ssse3"].map((kind) => {
      const object = resolve(output, `opt-${kind}.o`);
      run(compiler, [
        ...flags,
        `-m${kind}`,
        `-Dfill_segment=mhfe_fill_segment_${kind}`,
        "-c",
        "vendor/phc-winner-argon2/src/opt.c",
        "-o",
        object,
      ]);
      return object;
    });
    const simd = resolve(output, "argon2-simd");
    run(compiler, [
      ...flags,
      "-msse2",
      "-DMHFE_AUDIT_SIMD",
      probe,
      ...objects,
      ...optimized,
      "src/engine/argon2_simd.c",
      "-o",
      simd,
    ]);
    run(simd, []);
    run(simd, ["--wrong-expected"], 2, /tag mismatch/);
  }
  const tripwire = resolve(harness, "sanitizer-tripwire.c");
  const asan = resolve(output, "intentional-asan-failure");
  // ASan only, so UBSan cannot intercept this access before the intended ASan report.
  run(compiler, [
    "-O1",
    "-g",
    "-fno-omit-frame-pointer",
    "-fsanitize=address",
    "-DMHFE_AUDIT_ASAN",
    tripwire,
    "-o",
    asan,
  ]);
  run(asan, ["16"], "nonzero", /AddressSanitizer: heap-buffer-overflow/);
  const ubsan = resolve(output, "intentional-ubsan-failure");
  run(compiler, [
    "-O1",
    "-g",
    "-fsanitize=undefined",
    "-fno-sanitize-recover=all",
    tripwire,
    "-o",
    ubsan,
  ]);
  run(ubsan, ["1"], "nonzero", /runtime error: signed integer overflow/);
  unchanged(paths, before);
  writeFileSync(
    resolve(output, "receipt.json"),
    JSON.stringify(
      {
        sourceFiles: before,
        environment: Object.fromEntries(
          Object.entries(environment).filter(
            ([key]) => key.startsWith("ASAN_") || key.startsWith("UBSAN_"),
          ),
        ),
        records,
        artifacts: Object.fromEntries(
          [
            portable,
            ...(process.arch === "x64" ? [resolve(output, "argon2-simd")] : []),
            asan,
            ubsan,
          ].map((path) => [basename(path), sha(path)]),
        ),
        limits:
          "C-only instrumented observations; no Rust ABI execution, spill-erasure proof, race/timing analysis, full-cost or other-OS acceptance",
      },
      null,
      2,
    ) + "\n",
  );
  console.log("PASS: scoped C sanitizer acceptance and independently activated failure tripwires");
}
main();
