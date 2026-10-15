// @ts-check
/** @import { OptionsOf } from "../types/client-shared.d.ts" */
import {
  describeReference,
  requirePassphraseFits,
  CHECK_PASSPHRASE_REFERENCES,
} from "./references.js";
import { answerNoLength } from "./answers.js";
import { requireText, describeChoice, requireCallback } from "../../runtime/runtime.js";
/** @import { MhfeCheckEvidence } from "../client.d.ts" */
/** @import { CoreRuntime } from "./operation-runtime.js" */

/** CoreRehearsal owns this operation group behind the client's shared worker boundary. */
export class CoreRehearsal {
  /** @type {CoreRuntime} */
  #runtime;
  /** @param {CoreRuntime} runtime */
  constructor(runtime) {
    this.#runtime = runtime;
  }
  /**
   * The rehearsal check. `reference` is `{ address, coin, path? }` (strong), `{ fingerprint }`
   * (quick, weaker), `{ words }` (built-in check of a 12- to 21-word original; 0 detects the
   * length, and with `passphrase` a 24-word phrase drawn with the phrase + passphrase check is
   * found too) or `{ walletCheck: true }` (the phrase and passphrase check of a 24-word container,
   * with a passphrase). Resolves to `{ outcome, path, evidence }` and never to any part of the
   * phrase. `outcome` is "matches", "doesNotMatch" or "notVerified" under the specification's
   * length rules: exactly one verified reading or a wallet reference that matches; no reading or a
   * wallet reference that does not match; only readings nothing verifies, a 24-word reading
   * without a wallet reference (a wrong password gives one too, and a pass of the 16-bit check
   * does not verify it) or several lengths that pass with none of them stated. `path` is where a
   * matched address was found and null otherwise. `evidence` `{ builtInCheck, matchingLengths,
   * passed, walletCheck }` holds the original seed phrase's own checks from the same recovery: the
   * length of the one verified reading, every length whose built-in check passes, the checks that
   * passed as a page lists them, and the 16-bit check of the 24-word reading. Progress: "recover" 1 to 12, then once "compare".
   *
   * With `{ words: 0 }`, `onNoLength(evidence)` is called when detection found no verified
   * length, none or several (`evidence.matchingLengths`): ask the user how many words the original
   * seed phrase has, and return `{ words }` (12 to 21) or for 24 words `{ address, coin, path?,
   * passphrase? }` or `{ fingerprint, passphrase? }`, compared on the same recovery without its
   * rounds again; null keeps the result.
   * @param {OptionsOf<"check">} [options]
   */
  async check({
    container,
    password,
    passwordRepair,
    pim = 0,
    memoryLevel = 0,
    reference,
    passphrase = "",
    onProgress,
    onNoLength,
  } = {}) {
    requireText(container, "container");
    const [referenceKind, referenceValue, coin, path] = describeReference(reference);
    if (referenceValue !== "0") {
      requirePassphraseFits(referenceKind, passphrase, CHECK_PASSPHRASE_REFERENCES);
    }
    const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
    requireCallback(onNoLength, "onNoLength");
    const asksLength = onNoLength !== undefined;
    if (asksLength && (referenceKind !== "words" || referenceValue !== "0")) {
      throw new TypeError("onNoLength belongs only to { words: 0 }, the length detected.");
    }
    return this.#runtime.long(
      {
        operation: "check",
        container,
        choice,
        position,
        referenceKind,
        reference: referenceValue,
        coin,
        path,
        asksLength,
      },
      {
        password,
        pim,
        memoryLevel,
        onProgress,
        passphrase,
        handlers: asksLength
          ? {
              noLength: (/** @type {MhfeCheckEvidence} */ evidence) =>
                answerNoLength(onNoLength, evidence),
            }
          : {},
      },
    );
  }
}
