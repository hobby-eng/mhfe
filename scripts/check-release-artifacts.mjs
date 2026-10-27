// Prints the library's test binary, which cargo names in its JSON messages, for
// scripts/check-release-artifacts.sh:
//
//   cargo test --locked --lib --no-run --message-format=json | \
//     node scripts/check-release-artifacts.mjs --test-binary
import { readFileSync } from "node:fs";

if (process.argv.slice(2).join(" ") !== "--test-binary") {
  console.error("usage: node scripts/check-release-artifacts.mjs --test-binary");
  process.exit(2);
}
for (const line of readFileSync(0, "utf8").split("\n")) {
  if (line.trim() === "") continue;
  const message = JSON.parse(line);
  if (
    message.reason === "compiler-artifact" &&
    message.executable &&
    message.target.name === "mhfe"
  ) {
    console.log(message.executable);
  }
}
