// Rust lexical scopes shared by static gates; contents of literals never count as code.

import { RustSource } from "./rust-source.mjs";

/** Whole-source code with comments and literal contents blanked, preserving line offsets. */
export function rustCode(source) {
  return new RustSource(source).code();
}

/** Scope changes of a lexical Rust line whose literals and comments are already blanked. */
export function rustScopeDelta(code) {
  return {
    braces: (code.match(/\{/gu) ?? []).length - (code.match(/\}/gu) ?? []).length,
    parentheses: (code.match(/\(/gu) ?? []).length - (code.match(/\)/gu) ?? []).length,
  };
}

/**
 * The lines of Rust `lines` outside its tests and const contexts: an item after a `#[cfg(test)]`
 * or `#[cfg(all(test, …))]`, a `const` item or block and a `const fn` are left out up to the brace
 * that closes them, or to the `;` that ends a const item without one. Braces are counted on the
 * code with comments and literals removed, so unmatched braces in them change no scope.
 */
export function rustRunTimeLines(lines) {
  const kept = [];
  let depth = 0;
  /** The depth at which a left-out part ends, "statement" until a `;`, or null outside one. */
  let skipUntil = null;
  let pendingTest = false;
  for (const [index, code] of rustCode(lines.join("\n")).split("\n").entries()) {
    const trimmed = code.trim();
    if (skipUntil === null && /^#\[cfg\((?:all\()?test\b/u.test(trimmed)) pendingTest = true;
    const startsConst =
      /^(?:pub(?:\([a-z]+\))? )?const\b/u.test(trimmed) || /\bconst\s*\{/u.test(trimmed);
    const testItem = pendingTest && trimmed !== "" && !trimmed.startsWith("#");
    if (skipUntil === null && (startsConst || testItem)) {
      skipUntil = trimmed.includes("{") ? depth : "statement";
      pendingTest = false;
    }
    if (skipUntil === null) kept.push([index + 1, code]);
    depth += rustScopeDelta(code).braces;
    if (
      skipUntil === "statement" ? trimmed.endsWith(";") : skipUntil !== null && depth <= skipUntil
    ) {
      skipUntil = null;
    }
  }
  return kept;
}

/**
 * Production Rust lines, including constants, with test-only items omitted. Unlike runtime
 * panic checks, error type checks must also inspect const code and fields after a test-only enum
 * variant. This retains source line numbers and uses lexical scopes, never literal braces.
 */
export function rustProductionLines(lines) {
  const kept = [];
  let depth = 0;
  let parentheses = 0;
  let pending = false;
  let skipped = null;
  for (const [index, code] of rustCode(lines.join("\n")).split("\n").entries()) {
    const trimmed = code.trim();
    if (/^#\[cfg\((?:all\()?test\b/u.test(trimmed)) pending = true;
    if (skipped === null && pending && trimmed !== "" && !trimmed.startsWith("#")) {
      skipped = { depth, parentheses, opened: false };
      pending = false;
    }
    if (skipped === null && !pending) kept.push([index + 1, code]);
    const delta = rustScopeDelta(code);
    depth += delta.braces;
    parentheses += delta.parentheses;
    if (skipped !== null) {
      skipped.opened ||= code.includes("{");
      const atStart = depth <= skipped.depth && parentheses === skipped.parentheses;
      if (atStart && (skipped.opened || /[,;]$/u.test(trimmed))) skipped = null;
    }
  }
  return kept;
}
