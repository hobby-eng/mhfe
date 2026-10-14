// What the checks of the browser package read from the Rust sources: their string literals, and
// those that are vectors, which no script of the package and no module built without their part
// may carry (scripts/verify-browser-package.mjs, scripts/verify-single-modules.mjs).

/** The string literals of Rust source text, with their escapes resolved. */
export function rustStrings(source) {
  const strings = [];
  let index = 0;
  while (index < source.length) {
    if (source.startsWith("//", index)) {
      index = source.indexOf("\n", index);
      if (index === -1) break;
    } else if (source[index] === '"') {
      let text = "";
      index += 1;
      while (source[index] !== '"') {
        if (source[index] === "\\") {
          const next = source[index + 1];
          if (next === "\n") {
            // A line continuation: the line break and the next line's indentation are left out.
            index += 2;
            while (/\s/u.test(source[index])) index += 1;
            continue;
          }
          if (next === "u") {
            const end = source.indexOf("}", index);
            text += String.fromCodePoint(parseInt(source.slice(index + 3, end), 16));
            index = end + 1;
            continue;
          }
          text += { n: "\n", t: "\t", 0: "\0" }[next] ?? next;
          index += 2;
        } else {
          text += source[index];
          index += 1;
        }
      }
      strings.push(text);
      index += 1;
    } else {
      index += 1;
    }
  }
  return strings;
}

/**
 * Whether a string of a known-answers file is a vector: 8 or more characters with a digit and no
 * space (an address, a key, a digest), or a phrase of 12 words or more.
 */
export function isVectorText(text) {
  return (
    text.length >= 8 &&
    ((/[0-9]/u.test(text) && !text.includes(" ")) || text.split(" ").length >= 12)
  );
}
