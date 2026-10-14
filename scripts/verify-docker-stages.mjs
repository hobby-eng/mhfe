// Checks that every stage of packaging/Dockerfile.reproducible copies what the scripts it copies
// need (AUD-024-BLD001): the modules a copied JavaScript module imports, the scripts, packaging
// files, sources and vendored files a copied shell script names outside its comments, and the
// files of the repository beside a copied C file that it includes. A stage that copies
// the whole repository (`COPY . .`) is complete by construction; `COPY --from` copies build output
// and is not read.
//
//   node scripts/verify-docker-stages.mjs              the repository's Dockerfile
//   node scripts/verify-docker-stages.mjs --self-test  the check against controls it must decide

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { reported, runGate } from "./gate-command-line.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const DOCKERFILE = "packaging/Dockerfile.reproducible";
/** A relative module a JavaScript file imports, statically or dynamically. */
const IMPORT = /(?:\bfrom\s*|\bimport\s*\(?\s*)["'](\.{1,2}\/[^"']+)["']/gu;
/** A repository path a shell script names. */
const SHELL_PATH = /(?:^|[\s"'=(])((?:scripts|packaging|src|vendor)\/[\w./-]*[\w-])/gu;
/** A file a C file includes by a quoted name, looked for beside it first. */
const C_INCLUDE = /^\s*#\s*include\s+"([^"]+)"/gmu;

/** The usage, said with a refused command line. */
const USAGE = "usage: node scripts/verify-docker-stages.mjs [--self-test]";

/** The stages of a Dockerfile: each name with the sources of its plain COPY instructions. */
function stages(text) {
  /** @type {{ name: string, sources: string[] }[]} */
  const result = [];
  for (const line of text.replace(/\\\n/gu, " ").split("\n")) {
    const words = line.trim().split(/\s+/u);
    if (/^FROM$/iu.test(words[0])) {
      result.push({ name: words.at(-1) ?? "", sources: [] });
    } else if (/^COPY$/iu.test(words[0]) && result.length > 0) {
      const args = words.slice(1).filter((word) => !word.startsWith("--"));
      if (words.slice(1).some((word) => word.startsWith("--from"))) continue;
      result.at(-1).sources.push(...args.slice(0, -1));
    }
  }
  return result;
}

/** Whether `path` lies in what a stage copies: a copied file, or a file under a copied folder. */
function copied(sources, path) {
  return sources.some((source) => {
    const clean = source.replace(/\/$/u, "");
    return path === clean || path.startsWith(`${clean}/`);
  });
}

/** The first group of every match of `pattern` in `text`. */
function groups(text, pattern) {
  return [...text.matchAll(pattern)].flatMap((match) => (match[1] === undefined ? [] : [match[1]]));
}

/** What one copied file needs, as paths from the repository root; `read` tells which exist. */
function needs(path, text, read) {
  if (/\.(?:mjs|js)$/u.test(path)) {
    return groups(text, IMPORT).map((module) => normalize(join(dirname(path), module)));
  }
  if (/\.[ch]$/u.test(path)) {
    // Only an include found beside the file is the repository's; others come from -I folders.
    return groups(text, C_INCLUDE)
      .map((name) => normalize(join(dirname(path), name)))
      .filter((beside) => read(beside) !== null);
  }
  if (path.endsWith(".sh")) {
    const code = text
      .split("\n")
      .filter((line) => !line.trimStart().startsWith("#"))
      .join("\n");
    return groups(code, SHELL_PATH);
  }
  return [];
}

/** Every finding of a Dockerfile over the files that `read` gives, or null for a missing file. */
function stageFindings(dockerfile, read) {
  return stages(dockerfile).flatMap(({ name, sources }) => {
    if (sources.includes(".")) return [];
    return sources.flatMap((source) => {
      const text = read(source);
      if (text === null) return [];
      return needs(source, text, read)
        .filter((need) => !copied(sources, need))
        .map(
          (need) =>
            `${DOCKERFILE} stage ${name}: ${source} needs ${need}, which the stage does not copy`,
        );
    });
  });
}

/** The repository's file at `path`, or null for a folder or a missing file. */
function readFile(path) {
  const full = join(root, path);
  return existsSync(full) && statSync(full).isFile() ? readFileSync(full, "utf8") : null;
}

/** The check against controls it must decide right, and a refused command line. */
function selfTest() {
  const files = {
    "scripts/a.mjs": 'import { b } from "./b.mjs";\nconst c = await import("./c.mjs");\n',
    "scripts/b.mjs": "export const b = 1;\n",
    "scripts/c.mjs": "export const c = 1;\n",
    "scripts/run.sh": "# scripts/comment-only.sh is not run\nnode scripts/a.mjs\nls vendor/lib\n",
    "scripts/cc.sh": "cc src/x.c\n",
    "src/x.c": '#include "x.h"\n#include "core.h"\n',
    "src/x.h": "#define X 1\n",
  };
  const read = (path) => files[path] ?? null;
  const dockerfile = (copies) =>
    `FROM base AS first\nCOPY ${copies} scripts/\nRUN scripts/run.sh\n`;
  const controls = [
    [dockerfile("scripts/run.sh scripts/a.mjs scripts/b.mjs \\\n  scripts/c.mjs vendor/lib"), 0],
    [dockerfile("scripts/run.sh scripts/a.mjs scripts/b.mjs vendor/lib"), 1],
    [dockerfile("scripts/run.sh scripts/b.mjs scripts/c.mjs vendor/lib"), 1],
    [dockerfile("scripts/run.sh scripts/a.mjs scripts/b.mjs scripts/c.mjs"), 1],
    ["FROM base AS all\nCOPY . .\nCOPY --from=first /out /out\n", 0],
    ["FROM base AS c\nCOPY scripts/cc.sh src/x.c src/x.h scripts/\n", 0],
    ["FROM base AS c\nCOPY scripts/cc.sh src/x.c scripts/\n", 1],
    ["FROM base AS c\nCOPY scripts/cc.sh src/x.h scripts/\n", 1],
  ];
  for (const [index, [text, expected]] of controls.entries()) {
    const found = stageFindings(text, read);
    if (found.length !== expected) {
      throw new Error(`self-test: control ${index + 1} gives ${JSON.stringify(found)}`);
    }
  }
  console.log(`The Docker stage check decides all ${controls.length} of its controls right.`);
}

runGate(USAGE, {
  selfTest,
  check: () =>
    reported(
      stageFindings(readFileSync(join(root, DOCKERFILE), "utf8"), readFile),
      (count) => `${count} files a Docker stage needs are not copied into it.`,
      `Every stage of ${DOCKERFILE} copies what its scripts need.`,
    ),
});
