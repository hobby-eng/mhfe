// One bounded Rust lexical reader for source scopes, copy tokens and literal-based package gates.

const CHARACTER = /^(?:b)?'(?:\\(?:u\{[^}]*\}|x[\da-f]{2}|.)|[^'\\\r\n])'/iu;
const RAW = /^(b|c)?r(#*)"/u;
const QUOTED = /^(b|c)?"/u;
const LIFETIME = /^'[\p{ID_Start}_][\p{ID_Continue}_]*/u;
const ESCAPES = { n: "\n", r: "\r", t: "\t", 0: "\0", "\\": "\\", '"': '"', "'": "'" };
// Rust permits up to 255 hashes around a raw literal (Rust Reference, Tokens).
const MAX_RAW_HASHES = 255;

/**
 * Lexical spans of compiler input, retaining source offsets and line endings. This is not a
 * Rust parser or name resolver. Unterminated comments/string literals and unsupported text decoding
 * fail rather than hiding input from a gate. All scans stop at the source length.
 */
export class RustSource {
  #source;

  constructor(source) {
    if (typeof source !== "string") throw new TypeError("Rust source must be text.");
    this.#source = source;
  }

  /** A comment, string, character or lifetime starting at `from`, or null for ordinary code. */
  spanAt(from) {
    const source = this.#source;
    if (!Number.isSafeInteger(from) || from < 0 || from >= source.length)
      throw new RangeError("Rust source offset is outside the input.");
    if (source.startsWith("//", from)) {
      const end = source.indexOf("\n", from);
      return { kind: "comment", from, end: end === -1 ? source.length : end };
    }
    if (source.startsWith("/*", from)) return { kind: "comment", from, end: this.#blockEnd(from) };
    const rest = source.slice(from);
    const raw = RAW.exec(rest);
    if (raw !== null) {
      const hashes = raw[2].length;
      if (hashes > MAX_RAW_HASHES) throw new Error("Rust raw literal has too many hashes.");
      const start = from + raw[0].length;
      const close = source.indexOf('"' + raw[2], start);
      if (close === -1) throw new Error("Unterminated Rust raw literal.");
      return {
        kind: "string",
        from,
        start,
        close,
        end: close + hashes + 1,
        prefix: raw[1] ?? "",
        raw: true,
      };
    }
    const quoted = QUOTED.exec(rest);
    if (quoted !== null) {
      const start = from + quoted[0].length;
      const close = this.#quoteEnd(start);
      return {
        kind: "string",
        from,
        start,
        close,
        end: close + 1,
        prefix: quoted[1] ?? "",
        raw: false,
      };
    }
    const character = CHARACTER.exec(rest);
    if (character !== null) return { kind: "character", from, end: from + character[0].length };
    const lifetime = LIFETIME.exec(rest);
    return lifetime === null ? null : { kind: "lifetime", from, end: from + lifetime[0].length };
  }

  /** Every non-code span, in source order; an ordinary code character advances by one. */
  *spans() {
    let at = 0;
    while (at < this.#source.length) {
      const span = this.spanAt(at);
      if (span === null) at += 1;
      else {
        yield span;
        at = span.end;
      }
    }
  }

  /** Code with comments/strings/characters blanked, preserving offsets, newlines and lifetimes. */
  code() {
    const pieces = [];
    let at = 0;
    for (const span of this.spans()) {
      if (span.kind === "lifetime") continue;
      pieces.push(this.#source.slice(at, span.from));
      pieces.push(
        this.#source
          .slice(span.from, span.end)
          .replace(/[^\r\n]/gu, (character) => " ".repeat(character.length)),
      );
      at = span.end;
    }
    pieces.push(this.#source.slice(at));
    return pieces.join("");
  }

  /**
   * String bodies with Rust escapes/CRLF resolved, including UTF-8 byte and C strings (without
   * the implicit C terminator). A non-UTF-8 byte/C body is refused: text gates cannot represent
   * its bytes faithfully as a JavaScript string for subsequent UTF-8 artifact searches.
   */
  strings() {
    return [...this.spans()]
      .filter((span) => span.kind === "string")
      .map((span) => this.#value(span));
  }

  #blockEnd(from) {
    let depth = 1;
    let at = from + 2;
    while (at < this.#source.length) {
      if (this.#source.startsWith("/*", at)) {
        depth += 1;
        at += 2;
      } else if (this.#source.startsWith("*/", at)) {
        depth -= 1;
        at += 2;
        if (depth === 0) return at;
      } else at += 1;
    }
    throw new Error("Unterminated Rust block comment.");
  }

  #quoteEnd(start) {
    for (let at = start; at < this.#source.length; at += 1) {
      if (this.#source[at] === '"') return at;
      if (this.#source[at] === "\\") at += 1;
    }
    throw new Error("Unterminated Rust quoted literal.");
  }

  #escape(body, at, prefix) {
    const next = body[at + 1];
    if (Object.hasOwn(ESCAPES, next)) return { text: ESCAPES[next], end: at + 2 };
    if (next === "x") {
      const digits = body.slice(at + 2, at + 4);
      if (!/^[\da-f]{2}$/iu.test(digits)) throw new Error("Invalid Rust hexadecimal escape.");
      const byte = Number.parseInt(digits, 16);
      if (prefix === "" && byte > 0x7f) throw new Error("Non-ASCII Rust string byte escape.");
      return { byte, end: at + 4 };
    }
    if (next === "u" && prefix !== "b") {
      const escape = /^\\u\{([\da-f][\da-f_]*)\}/iu.exec(body.slice(at));
      const digits = escape?.[1].replaceAll("_", "") ?? "";
      const scalar = Number.parseInt(digits, 16);
      if (
        escape === null ||
        digits.length > 6 ||
        scalar > 0x10ffff ||
        (scalar >= 0xd800 && scalar <= 0xdfff)
      )
        throw new Error("Invalid Rust Unicode escape.");
      return { text: String.fromCodePoint(scalar), end: at + escape[0].length };
    }
    throw new Error("Unsupported Rust escape.");
  }

  #value(span) {
    const body = this.#source.slice(span.start, span.close).replaceAll("\r\n", "\n");
    if (body.includes("\r")) throw new Error("Bare carriage return in Rust literal.");
    let text = "";
    const bytes = [];
    const encoder = new TextEncoder();
    for (let at = 0; at < body.length;) {
      let token;
      if (!span.raw && body[at] === "\\") {
        if (body[at + 1] === "\n") {
          at += 2;
          while (at < body.length && /[\t\n\r ]/u.test(body[at])) at += 1;
          continue;
        }
        token = this.#escape(body, at, span.prefix);
      } else {
        const character = String.fromCodePoint(body.codePointAt(at));
        if (span.prefix === "b" && character.codePointAt(0) > 0x7f)
          throw new Error("Non-ASCII character in Rust byte literal.");
        token = { text: character, end: at + character.length };
      }
      at = token.end;
      if (span.prefix === "") text += token.text ?? String.fromCodePoint(token.byte);
      else if (token.byte !== undefined) bytes.push(token.byte);
      else bytes.push(...encoder.encode(token.text));
    }
    if (span.prefix !== "") {
      if (span.prefix === "c" && bytes.includes(0)) throw new Error("NUL in Rust C string.");
      try {
        // A literal's leading U+FEFF is data, not an input-file encoding marker.
        text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
          new Uint8Array(bytes),
        );
      } catch {
        throw new Error("Non-UTF-8 Rust byte/C literal is unsupported by text gates.");
      }
    }
    return text;
  }
}
