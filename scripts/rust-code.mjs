// Rust lexical scopes shared by static gates; contents of literals never count as code.

/** Rust code with comments and string/character contents blanked; braces there affect no scope.
 * `state` carries multiline strings and nested block comments between lines.
 * @param {string} line
 * @param {{ quoted: string | null, block: number }} state */
export function rustCode(line, state) {
  let code = "";
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (state.block > 0) {
      if (line.startsWith("/*", index)) {
        state.block += 1;
        index += 1;
      } else if (line.startsWith("*/", index)) {
        state.block -= 1;
        index += 1;
      }
    } else if (state.quoted !== null) {
      if (state.quoted === '"' && character === "\\") index += 1;
      else if (line.startsWith(state.quoted, index)) {
        index += state.quoted.length - 1;
        state.quoted = null;
      }
    } else if (line.startsWith("//", index)) {
      break;
    } else if (line.startsWith("/*", index)) {
      state.block = 1;
      index += 1;
    } else if (character === '"') {
      state.quoted = '"';
    } else {
      const raw = /^(?:b)?r(#+)?"/u.exec(line.slice(index));
      const char = /^'(?:\\(?:u\{[\da-f_]+\}|x[\da-f]{2}|.)|[^'\\])'/iu.exec(line.slice(index));
      if (raw !== null) {
        state.quoted = '"' + (raw[1] ?? "");
        index += raw[0].length - 1;
      } else if (char !== null) index += char[0].length - 1;
      else code += character;
    }
  }
  return code;
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
  /** @type {{ quoted: string | null, block: number }} */
  const lexical = { quoted: null, block: 0 };
  for (const [index, line] of lines.entries()) {
    const code = rustCode(line, lexical);
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
  const lexical = { quoted: null, block: 0 };
  let depth = 0;
  let parentheses = 0;
  let pending = false;
  let skipped = null;
  for (const [index, line] of lines.entries()) {
    const code = rustCode(line, lexical);
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
