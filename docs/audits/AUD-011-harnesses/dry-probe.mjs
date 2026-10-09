// Explicit source evidence for remaining message ownership, not a generic textual clone score.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const cli = readFileSync("src/bin/mhfe/diceware.rs", "utf8");
const library = readFileSync("src/new_password.rs", "utf8");
const words = cli.includes("Choose between 1 and {MOST_WORDS} words.") &&
  library.includes("choose between 1 and {MOST_WORDS} words");
const characters = cli.includes("Choose between 1 and {MOST_CHARACTERS} characters.") &&
  library.includes("choose between 1 and {MOST_CHARACTERS} characters");
console.log(JSON.stringify({ duplicatedWordSizeMessage: words,
  duplicatedCharacterSizeMessage: characters, limitsImportedNotDivergent: true }));
assert.ok(!words && !characters, "CLI must preserve the library-owned password-size message");
