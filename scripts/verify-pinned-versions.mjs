// Keeps every copy of a pinned version or provenance value equal to its source: a value has one
// source, and a copy that a file cannot avoid (a Dockerfile, a workflow, a document) is kept in step
// by a check. A pin names the file and the text that define the value, and its copies: files and
// texts each of whose matches must give the same value. A copy text that no longer matches at all
// is reported too, so that a reworded line cannot leave the check unseen.
//
// A text is written as it stands in the file: "{}" is the value, a space any white space, and a
// leading "^" the start of a line.
//
// scripts/package-release.sh reads the Argon2 commit and the Emscripten version of BUILD-INFO.txt
// from their sources itself, and CI reads .node-version and rust-toolchain.toml itself: they hold
// no copy.
//
//   node scripts/verify-pinned-versions.mjs              the repository
//   node scripts/verify-pinned-versions.mjs --self-test  the check against controls it must decide

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { reported, runGate } from "./gate-command-line.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
/** A version of three numbers. */
const VERSION = String.raw`\d+\.\d+\.\d+`;
/** A full Git commit hash. */
const COMMIT = "[0-9a-f]{40}";

/**
 * The pinned values: a name, the pattern of the value, the source as [file, text], and the copies
 * as [file, text, …].
 */
const PINS = [
  {
    name: "the version of mhfe",
    value: VERSION,
    source: ["Cargo.toml", '^version = "{}"'],
    copies: [["CITATION.cff", "^version: {}"]],
  },
  {
    name: "the vendored Argon2 commit",
    value: COMMIT,
    source: ["vendor/phc-winner-argon2.md", "| Commit | `{}`"],
    copies: [
      ["src/vectors.rs", "phc-winner-argon2 commit \\ {}"],
      ["THIRD_PARTY_NOTICES.md", "commit `{}`"],
    ],
  },
  {
    name: "Emscripten",
    value: VERSION,
    source: ["scripts/build-argon2-wasm.sh", '^expected_emscripten="{}"'],
    copies: [
      ["packaging/Dockerfile.reproducible", "Emscripten {}", "emscripten/emsdk:{}@"],
      [
        ".github/workflows/ci.yml",
        "Emscripten {}",
        "--branch {} https://github.com/emscripten-core/emsdk",
        'emsdk" install {}',
        'emsdk" activate {}',
      ],
      [
        "docs/DEVELOPMENT.md",
        "Emscripten {}",
        "--branch {} https://github.com/emscripten-core/emsdk",
        "emsdk install {}",
        "emsdk activate {}",
        "emscripten/emsdk:{}",
      ],
      ["AGENTS.md", "Emscripten {}"],
      ["THIRD_PARTY_NOTICES.md", "Emscripten {}"],
      ["scripts/build-wasm.sh", "Emscripten {}"],
      ["scripts/check.sh", "Emscripten {}"],
      ["scripts/remove-network-code.mjs", "Emscripten {}"],
    ],
  },
  {
    name: "wasm-bindgen",
    value: VERSION,
    source: ["scripts/bind-wasm.sh", '^expected_bindgen="wasm-bindgen {}"'],
    copies: [
      ["Cargo.toml", 'wasm-bindgen = { version = "={}"'],
      ["packaging/Dockerfile.reproducible", "wasm-bindgen-cli --version {}", '"wasm-bindgen {}"'],
      [".github/workflows/ci.yml", "wasm-bindgen-cli --version {}"],
      ["docs/DEVELOPMENT.md", "wasm-bindgen command-line tool {}", "wasm-bindgen-cli --version {}"],
      [
        "THIRD_PARTY_NOTICES.md",
        "wasm-bindgen command-line tool {}",
        "`wasm-bindgen-cli-support` {}",
      ],
      ["scripts/bind-wasm.sh", "Needs wasm-bindgen {}"],
      ["scripts/build-wasm.sh", "wasm-bindgen {}"],
      ["scripts/check.sh", "wasm-bindgen {}"],
    ],
  },
  {
    name: "Node.js",
    value: VERSION,
    source: [".node-version", "^{}"],
    copies: [["packaging/Dockerfile.reproducible", "^ARG NODE_VERSION={}"]],
  },
  {
    name: "Rust",
    value: VERSION,
    source: ["rust-toolchain.toml", '^channel = "{}"'],
    copies: [
      ["packaging/Dockerfile.reproducible", "--default-toolchain {}", '"rustc {}"'],
      ["AGENTS.md", "Rust {}"],
    ],
  },
];

/** The usage, said with a refused command line. */
const USAGE = "usage: node scripts/verify-pinned-versions.mjs [--self-test]";

/** The pattern of a text: its characters literally, the value as the only group. */
function textPattern(text, value) {
  const lineStart = text.startsWith("^");
  const body = (lineStart ? text.slice(1) : text)
    .split("{}")
    .map((part) =>
      part.replace(/[.*+?^${}()|[\]\\]/gu, String.raw`\$&`).replace(/ /gu, String.raw`\s+`),
    )
    .join(`(${value})`);
  return new RegExp(`${lineStart ? "^" : ""}${body}`, "dgmu");
}

/** Every finding of the pins over the files that `read` gives by their path from the root. */
function pinFindings(pins, read) {
  return pins.flatMap((pin) => {
    const [sourcePath, sourceText] = pin.source;
    const defined = [...read(sourcePath).matchAll(textPattern(sourceText, pin.value))];
    if (defined.length !== 1) {
      return [`${pin.name}: ${sourcePath} defines it ${defined.length} times, not once`];
    }
    const expected = defined[0][1];
    return pin.copies.flatMap(([path, ...texts]) =>
      texts.flatMap((text) => {
        const found = [...read(path).matchAll(textPattern(text, pin.value))];
        if (found.length === 0) return [`${pin.name}: ${path} no longer says "${text}"`];
        return found
          .filter((match) => match[1] !== expected)
          .map((match) => `${pin.name}: ${path} says ${match[1]}, ${sourcePath} ${expected}`);
      }),
    );
  });
}

/** The repository's file at `path`, by its path from the root. */
function readFile(path) {
  return readFileSync(join(root, path), "utf8");
}

/** The value turned into another of the same form: each 0 into 1, every other character into 0. */
function otherValue(value) {
  return value.replace(/[0-9a-f]/gu, (character) => (character === "0" ? "1" : "0"));
}

/** `text` with the value of the first match of `pattern` replaced, or removed with its text. */
function changed(text, pattern, remove) {
  const match = pattern.exec(text);
  if (match === null || match.indices === undefined) throw new Error("self-test: no match");
  const [start, end] = remove ? match.indices[0] : match.indices[1];
  return text.slice(0, start) + (remove ? "" : otherValue(match[1])) + text.slice(end);
}

/**
 * The controls over the repository's own files: each copy's value changed and each source removed,
 * one at a time, must give exactly one finding.
 */
function controls() {
  return PINS.flatMap((pin) => {
    const [sourcePath, sourceText] = pin.source;
    const removed = { path: sourcePath, pattern: textPattern(sourceText, pin.value), remove: true };
    const copies = pin.copies.flatMap(([path, ...texts]) =>
      texts.map((text) => ({ path, pattern: textPattern(text, pin.value), remove: false })),
    );
    return [removed, ...copies].map((control) => ({ ...control, pin }));
  });
}

/** The check against controls it must decide right, and a refused command line. */
function selfTest() {
  if (pinFindings(PINS, readFile).length > 0) {
    throw new Error("self-test: the repository's own files must pass first");
  }
  const all = controls();
  for (const { path, pattern, remove, pin } of all) {
    const text = changed(readFile(path), pattern, remove);
    const found = pinFindings([pin], (read) => (read === path ? text : readFile(read)));
    if (found.length !== 1) {
      throw new Error(`self-test: ${pattern.source} in ${path} gives ${JSON.stringify(found)}`);
    }
  }
  console.log(`The pinned versions decide all ${all.length} of their controls right.`);
}

runGate(USAGE, {
  selfTest,
  check: () =>
    reported(
      pinFindings(PINS, readFile),
      (count) => `${count} copies differ from their source.`,
      "Every copy of a pinned value equals its source.",
    ),
});
