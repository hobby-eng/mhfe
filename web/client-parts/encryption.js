// @ts-check
/** @import { OptionsOf } from "../types/client-shared.d.ts" */
import { requireWalletPassphrase, requireRepairWordCount, requireWordCount } from "./input.js";
import {
  requireText,
  requireBoolean,
  requireCallback,
  describeChoice,
} from "../../runtime/runtime.js";
/** @import { CoreRuntime } from "./operation-runtime.js" */

/** CoreEncryption owns this operation group behind the client's shared worker boundary. */
export class CoreEncryption {
  /** @type {CoreRuntime} */
  #runtime;
  /** @param {CoreRuntime} runtime */
  constructor(runtime) {
    this.#runtime = runtime;
  }
  /**
   * Encrypts an original phrase. `passwordRepeat` is the password typed a second time: a typing
   * mistake in the password would lock the phrase away for good. `passwordRepair` is the choice of
   * the check word review (MhfePasswords.review): "asTyped" (the default), "corrected" or
   * `{ repair: position }`. The encryption then decrypts the container's words again and compares
   * the result with the phrase, so it runs 24 rounds: "encrypt" 1 to 12, then "check" 13 to 24.
   *
   * Resolves only after that check has passed to `{ container, suiteId, containerFingerprint,
   * builtInCheck, otherLengths, repairWords, repairProfile, keep: [{ item, ... }] }`; a failed
   * check rejects with VERIFICATION_FAILED. `keep` lists what the owner keeps, in order:
   * containerWords {words}, password, passphrase or passphraseIfAny, repairWords, pim {value},
   * memoryLevel {value}, wordCount {words}.
   *
   * The container has 24 words. With `sameLength: true`, which only the user's own choice may
   * set after the page has shown its consequences, a 12- to 21-word phrase gives a container of
   * its own length instead. `repairWordCount` 2, 4, 6 or 8 makes repair words, which come only
   * with the result. `walletHasPassphrase` says whether the wallet has a BIP39 passphrase, only
   * where the page knows it, such as after drawPhrase(): true adds it to what to keep, since MHFE
   * encrypts only the phrase, and false leaves it out. Left out or null, `keep` names any BIP39
   * passphrase of the wallet (passphraseIfAny) instead: the page need not ask.
   *
   * `onUnverified({ container, containerFingerprint })` is called after the first 12 rounds, so
   * that the page can show the container while the check runs, marked as not yet verified, and
   * ask the user not to rely on it until the check ends, and later say how the check ended:
   * verified, wrong (VERIFICATION_FAILED), or not verified
   * (cancelled or any other error).
   * @param {OptionsOf<"encrypt">} [options]
   */
  async encrypt({
    phrase,
    password,
    passwordRepeat,
    passwordRepair,
    pim = 0,
    memoryLevel = 0,
    sameLength = false,
    repairWordCount = 0,
    walletHasPassphrase,
    onProgress,
    onUnverified,
  } = {}) {
    requireText(phrase, "phrase");
    requireBoolean(sameLength, "sameLength");
    if (walletHasPassphrase !== undefined && walletHasPassphrase !== null) {
      requireWalletPassphrase(walletHasPassphrase);
    }
    requireRepairWordCount(repairWordCount);
    requireCallback(onUnverified, "onUnverified");
    const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
    return this.#runtime.long(
      {
        operation: "encrypt",
        choice,
        position,
        sameLength,
        repairWordCount,
        walletHasPassphrase,
      },
      {
        phrase,
        password,
        passwordRepeat,
        pim,
        memoryLevel,
        onProgress,
        handlers: { unverified: onUnverified },
      },
    );
  }
  /**
   * Recovers the original phrase, twelve rounds, "recover". The container's word count selects
   * the suite. `words` is 0 for automatic detection or the known length. Resolves to `{ kind:
   * 'phrase' | 'ambiguous', candidates: [{ words, verified, status, phrase, suiteId,
   * fingerprintWithoutPassphrase, walletCheck, statedWords, otherLengths }] }`; `status` is
   * "verified", "noBuiltInCheck", "readAs24" or "readAs24Chosen". `walletCheck` is the 16-bit
   * wallet check of a 24-word reading with `passphrase`, the wallet's BIP39 passphrase or "" for
   * none, which every recovery evaluates: the container does not show whether the phrase was
   * made with the check, so a page asks for the passphrase when a 24-word reading comes out,
   * says why, and decrypts again with it, or asks before; null for other lengths. A pass makes a
   * right password very likely; a failure means something only if the wallet was made with the
   * check. A stated
   * length does not replace detection: a built-in check that passes takes precedence, and
   * `statedWords` then names the length stated; 24 stated words beside a check that passes give
   * "ambiguous", the checked reading first.
   * @param {OptionsOf<"decrypt">} [options]
   */
  async decrypt({
    container,
    password,
    passwordRepair,
    pim = 0,
    memoryLevel = 0,
    words = 0,
    passphrase = "",
    onProgress,
  } = {}) {
    requireText(container, "container");
    requireWordCount(words);
    const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
    return this.#runtime.long(
      { operation: "decrypt", container, choice, position, words },
      { password, pim, memoryLevel, onProgress, passphrase },
    );
  }
}
