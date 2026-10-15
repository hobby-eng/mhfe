// @ts-check
/** @import { OptionsOf } from "../types/client-shared.d.ts" */
import { requireSettingValues } from "./input.js";
import { requireText, encodeSecret } from "../../runtime/runtime.js";
/** @import { CoreRuntime } from "./operation-runtime.js" */

/** CoreReads owns this operation group behind the client's shared worker boundary. */
export class CoreReads {
  /** @type {CoreRuntime} */
  #runtime;
  /** @param {CoreRuntime} runtime */
  constructor(runtime) {
    this.#runtime = runtime;
  }
  /**
   * The core's fixed values: `{ version, suiteId, sameLengthSuiteId, rounds, maxPim,
   * maxMemoryLevel, highestBrowserMemoryLevel, wordCounts, builtInCheckWordCounts,
   * repairWordCounts, recommendedRepairWords, repairCapacities, hiddenWalletRefusals,
   * decoyScanGap, argon2Parts }`.
   */
  async parameters() {
    return this.#runtime.quick({ operation: "parameters" });
  }
  /**
   * Reads an original phrase the way a person may have typed it (any case and spacing, words cut
   * to four letters) and resolves to `{ phrase, words, otherLengths, containers: [{ sameLength,
   * words, wrongWordPassesOneIn, otherLengths }] }`: every word written out, for showing back, and
   * the containers it can be encrypted into, each with its own `otherLengths`, empty for a
   * same-length one; the top-level `otherLengths` is the 24-word container's. `otherLengths` is
   * almost always empty; when it is not, automatic detection would not give this phrase on its own
   * after recovery, so the page tells the user to note the word count and choose it then. Rejects
   * an invalid phrase.
   * @param {unknown} phrase
   */
  async readPhrase(phrase) {
    requireText(phrase, "phrase");
    await this.#runtime.ready();
    // The phrase goes as bytes that the worker and the WebAssembly wipe, as a password does.
    const message = { operation: "describePhrase", phrase: encodeSecret(phrase, "phrase") };
    return this.#runtime.quick(message);
  }
  /**
   * Like readPhrase for a container: resolves to `{ container, words, suiteId, phraseLengths,
   * builtInCheckLengths, confirmationFor, hiddenWallets, offersWalletCheck, containerFingerprint }`.
   * `confirmationFor` says, for each phrase length, what confirms a recovery to encrypt again:
   * "builtInCheck" for a stated 12- to 21-word length of a 24-word container, and "walletOrOwner"
   * for every other length and for "0", the length detected, which the built-in check alone does
   * not confirm.
   * @param {unknown} container
   */
  async readContainer(container) {
    requireText(container, "container");
    await this.#runtime.ready();
    return this.#runtime.quick({ operation: "describeContainer", container });
  }
  /**
   * What to keep of the old container of a rekey until the funds of the wallets that other
   * passwords open on it are moved, as the library lists it: `[{ item }]` with "oldContainer" and
   * "oldPasswords", then `{ item: "pim", value }` and `{ item: "memoryLevel", value }` where
   * `pim` or `memoryLevel`, the old container's settings, is not 0. Say it to every user before a
   * rekey, whatever the container, so that it says nothing about one: those wallets do not move to
   * the new container, and the user's own wallet's addresses do not change.
   * @param {OptionsOf<"keepOldContainer">} [options]
   */
  async keepOldContainer({ pim = 0, memoryLevel = 0 } = {}) {
    requireSettingValues(pim, memoryLevel);
    await this.#runtime.ready();
    return this.#runtime.quick({ operation: "keepOldContainer", pim, memoryLevel });
  }
  /**
   * The candidates of a container phrase with words typed as "?" (MhfeRepair.inspectContainer
   * says "marked"), before a search without its repair words: `{ missing, candidates,
   * offersWalletSearch, offersOwnChecks }`, the positions from 1, how many candidate containers
   * pass the BIP39 checksum, and which searches with the password the library offers for them:
   * the original seed phrase's wallet (searchWallet() with an address or fingerprint) and its own
   * checks (searchWallet() with `{ builtInCheck: true }` or `{ walletCheck: true }`). The decoy
   * search (searchDecoy()) is always offered. More than two missing words reject with
   * TOO_MANY_MISSING_WORDS.
   * @param {OptionsOf<"searchCandidates">} [options]
   */
  async searchCandidates({ container } = {}) {
    requireText(container, "container");
    await this.#runtime.ready();
    return this.#runtime.quick({ operation: "searchCandidates", container });
  }
}
