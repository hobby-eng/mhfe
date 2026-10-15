// @ts-check
/** @import { OptionsOf } from "../types/client-shared.d.ts" */
import { DECOY_SCAN_GAP } from "./values.js";
import {
  describeSearchReference,
  requirePassphraseFits,
  CHECK_PASSPHRASE_REFERENCES,
} from "./references.js";
import { requireText, describeChoice } from "../../runtime/runtime.js";
/** @import { CoreRuntime } from "./operation-runtime.js" */

/** CoreSearch owns this operation group behind the client's shared worker boundary. */
export class CoreSearch {
  /** @type {CoreRuntime} */
  #runtime;
  /** @param {CoreRuntime} runtime */
  constructor(runtime) {
    this.#runtime = runtime;
  }
  /**
   * Searches for the words of a container phrase typed as "?", up to two, with the decoy wallet:
   * the container itself as a wallet, whose master key fingerprint the page showed under the
   * container. No password and no Argon2: seconds for one word, minutes for two. `reference` is
   * `{ address, coin, path? }` or `{ fingerprint }`, `passphrase` the BIP39 passphrase used with
   * the container phrase, "" for none: ask the user whether one is used. For two missing words an
   * address is searched among the first `scanGap` receiving and as many change addresses of the
   * first account: parameters().decoyScanGap by default, the usual gap of a wallet; more takes
   * longer in proportion.
   * Progress: `{ stage: "search", candidate, candidates }`.
   * Resolves to `{ found, container, containerFingerprint, words: [{ position, word }], path,
   * candidates }`, `container` null when none matched. Every candidate is compared: a reference
   * that more than one matches, as a fingerprint, a 32-bit check, can among the many candidates
   * of two missing words, rejects with SEVERAL_CANDIDATES_MATCH, and an address tells them apart.
   * Show the words found and use the container only after the user has said so.
   * @param {OptionsOf<"searchDecoy">} [options]
   */
  async searchDecoy({
    container,
    reference,
    passphrase = "",
    scanGap = DECOY_SCAN_GAP,
    onProgress,
  } = {}) {
    requireText(container, "container");
    if (!Number.isSafeInteger(scanGap)) {
      throw new TypeError("scanGap must be a whole number of addresses.");
    }
    const [referenceKind, referenceValue, coin, path] = describeSearchReference(reference, false);
    return this.#runtime.long(
      {
        operation: "searchDecoy",
        container,
        referenceKind,
        reference: referenceValue,
        coin,
        path,
        scanGap,
      },
      { onProgress, passphrase, noPassword: true },
    );
  }
  /**
   * Searches for the one word of a container phrase typed as "?" with the owner's wallet: every
   * candidate is recovered with `password` at the settings given, a full recovery each, at the
   * defaults about one and a half to two minutes in fast mode and four to seven in standard mode,
   * so that the page states the time first: the candidates of searchCandidates() times one
   * recovery in this mode. `reference` is `{ address, coin, path? }`, `{ fingerprint }`,
   * or the original seed phrase's own checks: `{ walletCheck: true }` with its BIP39 passphrase,
   * which takes the built-in check of a 12- to 21-word one and the phrase + passphrase check of a
   * 24-word one made by `mhfe new` (16 bits: a wrong candidate passes it about once in 65,536), or
   * `{ builtInCheck: true }`, which needs nothing and takes the built-in check alone. Two
   * missing words reject with TOO_MANY_MISSING_WORDS, a same-length container with the built-in
   * check with NO_BUILT_IN_CHECK. Progress: `{ stage: "search", candidate, candidates, round,
   * rounds }`. Resolves as searchDecoy().
   * @param {OptionsOf<"searchWallet">} [options]
   */
  async searchWallet({
    container,
    password,
    passwordRepair,
    pim = 0,
    memoryLevel = 0,
    reference,
    passphrase = "",
    onProgress,
  } = {}) {
    requireText(container, "container");
    const [referenceKind, referenceValue, coin, path] = describeSearchReference(reference, true);
    requirePassphraseFits(referenceKind, passphrase, CHECK_PASSPHRASE_REFERENCES);
    const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
    return this.#runtime.long(
      {
        operation: "searchWallet",
        container,
        choice,
        position,
        referenceKind,
        reference: referenceValue,
        coin,
        path,
      },
      { password, pim, memoryLevel, onProgress, passphrase },
    );
  }
}
