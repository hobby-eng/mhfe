// AUD-024 browser-isolation check: a BIP39 passphrase that the comparison does not take is refused,
// not dropped. MhfeClient.check() with a stated 12- to 21-word length ({ words: 12 }) compares the
// built-in check alone, which takes no passphrase (rehearsal::refuse_unused_passphrase), so a
// non-empty passphrase beside it must be refused, as searchWallet() refuses one beside
// { builtInCheck: true }; so must an onNoLength answer { words, passphrase }. Exits 1 when a case
// that must be refused resolves, or when a control does not behave as stated. Reduced-cost Argon2
// (in-process-worker.mjs); public test data only.
import {
  MhfeClient,
  PASSWORD,
  PHRASE_FINGERPRINT,
  REDUCED_COST_CONTAINER,
  ZERO_24,
  hooks,
  outcome,
  sources,
} from "./in-process-worker.mjs";

const client = new MhfeClient(sources());
const base = { container: REDUCED_COST_CONTAINER, password: PASSWORD };
let failed = false;
const report = (ok, name, result, detail = "") => {
  if (!ok) failed = true;
  console.log(`${ok ? "ok  " : "FAIL"} ${name}\n     ${result}${detail}`);
};
const refused = (result) => result.startsWith("rejected TypeError") || result.includes("INVALID_REQUEST");
const sent = [];
hooks.onPageMessage = (worker, message) => {
  const fields = message.type === "answer" ? message.value : message;
  if (fields?.passphrase instanceof Uint8Array) {
    sent.push(`${fields.referenceKind}=${fields.reference}, passphrase of ${fields.passphrase.byteLength} bytes`);
  }
};
const reached = () => (sent.length === 0 ? "" : `\n     the worker got: ${sent.join("; ")}`);

// Controls: a passphrase beside a fingerprint is used; one beside { builtInCheck: true } is refused.
sent.length = 0;
let result = await outcome(
  client.check({ ...base, reference: { fingerprint: PHRASE_FINGERPRINT }, passphrase: "TREZOR" }),
);
report(result.includes('"outcome":"doesNotMatch"'), "control: a passphrase beside a fingerprint is compared", result);
sent.length = 0;
result = await outcome(
  client.searchWallet({
    container: REDUCED_COST_CONTAINER.replace("slush", "?"),
    password: PASSWORD,
    reference: { builtInCheck: true },
    passphrase: "TREZOR",
  }),
);
report(refused(result), "control: a passphrase beside { builtInCheck: true } in searchWallet() is refused", result);

// The cases: a passphrase beside a stated length, and inside an onNoLength answer of a length.
sent.length = 0;
result = await outcome(client.check({ ...base, reference: { words: 12 }, passphrase: "TREZOR" }));
report(refused(result), "a passphrase beside { words: 12 } in check() is refused", result, reached());

const sealed = await client.encrypt({
  phrase: ZERO_24,
  password: PASSWORD,
  passwordRepeat: PASSWORD,
  walletHasPassphrase: false,
});
sent.length = 0;
result = await outcome(
  client.check({
    container: sealed.container,
    password: PASSWORD,
    reference: { words: 0 },
    onNoLength: () => ({ words: 12, passphrase: "TREZOR" }),
  }),
);
report(refused(result), "an onNoLength answer { words: 12, passphrase } is refused", result, reached());
process.exit(failed ? 1 : 0);
