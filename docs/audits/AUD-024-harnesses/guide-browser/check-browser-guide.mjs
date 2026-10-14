// AUD-024 guide-browser harness (review only; audit AUD-024 at commit b6fca69): runs the browser
// package of dist/ in Node, its workers in this process with Argon2 at reduced cost, and checks the
// behaviour the guide-browser findings expect. Each check prints "ok" or "FAILS" with what it saw;
// the harness exits 1 when any check fails. Public test data only. See README.md.
//
//   node docs/audits/AUD-024-harnesses/guide-browser/check-browser-guide.mjs
import { readFileSync } from "node:fs";

import {
  MhfeClient,
  MhfeWallet,
  PASSWORD,
  PHRASE,
  PHRASE_BIP84_ADDRESS,
  REDUCED_COST_CONTAINER,
  REPO,
  argon2Fault,
  moduleSources,
  sources,
} from "./in-process-package.mjs";

let failures = 0;
function check(name, passed, seen) {
  if (!passed) failures += 1;
  console.log(`${passed ? "ok   " : "FAILS"} ${name}: ${seen}`);
}
async function settle(promise) {
  try {
    return { value: await promise };
  } catch (error) {
    return { error };
  }
}
const shown = ({ value, error }) =>
  error === undefined
    ? `resolved ${JSON.stringify(value)}`
    : `${error.name} ${error.code ?? "(no code)"}: ${error.message}`;

const client = new MhfeClient(sources);
const wallet = new MhfeWallet(moduleSources);

// 1. A whole number above 2^32 - 1 is not refused as "not a whole number", and no message turns
//    an API name into another word ("ScanGap").
{
  const got = await settle(
    wallet.describeAddress({ address: PHRASE_BIP84_ADDRESS, coin: "bitcoin", scanGap: 2 ** 32 }),
  );
  const text = got.error?.message ?? "";
  check(
    "scanGap 2^32 is refused in the library's words",
    got.error !== undefined && !/whole number/u.test(text) && !text.startsWith("ScanGap"),
    shown(got),
  );
}

// 2. Out-of-range numbers of one parameter get one kind of refusal: an MhfeError with a code.
{
  const low = await settle(
    client.searchDecoy({
      container: REDUCED_COST_CONTAINER.replace(/^slush/u, "?"),
      reference: { fingerprint: "73c5da0a" },
      scanGap: 0,
    }),
  );
  check(
    "searchDecoy scanGap 0, a number, rejects with an MhfeError code (docs/API.md:975-980)",
    typeof low.error?.code === "string",
    shown(low),
  );
}

// 3. A refused onNoLength answer is a TypeError, as docs/BROWSER-PACKAGE.md:214-216 says.
{
  const got = await settle(
    client.check({
      container: REDUCED_COST_CONTAINER,
      password: "not the password",
      reference: { words: 0 },
      onNoLength: () => ({ words: 0 }),
    }),
  );
  check("onNoLength answering detection again is a TypeError", got.error instanceof TypeError, shown(got));
}

// 4. CALLBACK_FAILED names the callback the page passed.
{
  const got = await settle(
    client.encrypt({
      phrase: PHRASE,
      password: PASSWORD,
      passwordRepeat: PASSWORD,
      onUnverified: () => {
        throw new Error("the page's own error");
      },
    }),
  );
  check(
    "a failing onUnverified is named onUnverified",
    got.error?.code === "CALLBACK_FAILED" && got.error.message.includes("onUnverified"),
    shown(got),
  );
}

// 5. An Argon2 error of the page's build names its code once.
{
  argon2Fault.code = -33;
  const got = await settle(client.decrypt({ container: REDUCED_COST_CONTAINER, password: PASSWORD }));
  argon2Fault.code = null;
  const text = got.error?.message ?? "";
  check(
    "ARGON2_FAILED's message does not repeat the code",
    got.error?.code === "ARGON2_FAILED" && !text.includes("ARGON2_FAILED"),
    shown(got),
  );
}

// 6. One chosen word that cannot be used is refused as a word wish, not as the binding's places.
{
  const got = await settle(wallet.describeDraw({ chosen: [{ word: "abandon zoo", position: 3 }] }));
  check("a chosen word with a space is INVALID_WORD_WISH", got.error?.code === "INVALID_WORD_WISH", shown(got));
  const empty = await settle(wallet.describeDraw({ neverUse: ["", "zoo"] }));
  check("an empty word never to use is refused, not dropped", empty.error !== undefined, shown(empty));
}

// 7. A seed phrase may be given as UTF-8 bytes, as a password or a passphrase may.
{
  const got = await settle(wallet.fingerprint({ phrase: new TextEncoder().encode(PHRASE) }));
  check("wallet.fingerprint takes a phrase as bytes", got.value === "73c5da0a", shown(got));
}

// 8. Every operation a worker table serves is one a class sends.
{
  const tables = ["core-worker.js", "repair-worker.js", "passwords-worker.js", "wallet-worker.js"];
  const served = tables.filter((file) =>
    readFileSync(`${REPO}web/${file}`, "utf8").includes("packageVersion: () =>"),
  );
  check("no worker table serves the unused packageVersion operation", served.length === 0, served.join(", ") || "none");
}

// 9. searchCandidates' description is its own doc comment, not the one above keepOldContainer.
{
  const source = readFileSync(`${REPO}web/client.js`, "utf8");
  const at = source.indexOf("  async searchCandidates(");
  // The doc comment that ends right above the method.
  const comment = source.slice(source.lastIndexOf("/**", at), at);
  const described = comment.includes("The candidates of a container phrase");
  check(
    "searchCandidates' doc comment holds its description",
    described,
    described ? "found" : `the comment above it is ${JSON.stringify(comment.trim())}`,
  );
}

console.log(failures === 0 ? "Every check passes." : `${failures} checks fail.`);
process.exit(failures === 0 ? 0 : 1);
