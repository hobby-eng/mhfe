// @ts-check
/** @import { OptionsOf } from "../types/client-shared.d.ts" */
import {
  requireWalletPassphrase,
  requireWordCount,
  requireSettings,
  requireRepairWordCount,
} from "./input.js";
import {
  describeConfirmation,
  requirePassphraseFits,
  REKEY_PASSPHRASE_REFERENCES,
} from "./references.js";
import { answerOwner, answerConfirmAgain } from "./answers.js";
import {
  requireText,
  requireCallback,
  describeChoice,
  packageMismatch,
} from "../../runtime/runtime.js";
/** @import { ConfirmAgainRefusal, OwnerCheck, PageOwner } from "../types/client-shared.d.ts" */
/** @import { WorkerHandlers } from "../../runtime/runtime.js" */
/** @import { CoreRuntime } from "./operation-runtime.js" */

/** CoreRekey owns this operation group behind the client's shared worker boundary. */
export class CoreRekey {
  /** @type {CoreRuntime} */
  #runtime;
  /** @param {CoreRuntime} runtime */
  constructor(runtime) {
    this.#runtime = runtime;
  }
  /**
   * Re-encrypts a container with a new password or settings: rounds 1 to 12 recover it with the old
   * ones, 13 to 36 seal it again. Nothing is destroyed here: tell every user first what to keep of
   * the old container until the funds of the wallets that other passwords open on it are moved
   * (keepOldContainer()). `pim` and `memoryLevel` are
   * the old container's settings; `newPim`, `newMemoryLevel`, `newPasswordRepair` and
   * `repairWordCount` those of the new one, and `onProgress` and `onUnverified` work as for
   * encrypt().
   *
   * `words` is the phrase's word count, or 0 to detect it; a same-length container takes 0 or its
   * own length. With the length detected, `{ builtInCheck: true }` alone is refused before the
   * first round (REFERENCE_REQUIRED), as a 24-word original may pass a short check by chance; an
   * address or the fingerprint is compared with every reading, whatever its length, and the owner
   * confirms the one reading found. Several lengths that pass by accident reject
   * `{ builtInCheck: true }` and the owner with AMBIGUOUS_LENGTH, unless the owner's stated length
   * is one of them: rekey again confirmed by an address or the fingerprint, which compares every
   * reading, or by the owner with the length of the reading to compare stated. A stated length
   * whose built-in check fails while one other length's passes rejects `{ builtInCheck: true }`
   * with LENGTH_DIFFERS, as the check takes precedence: rekey again confirmed by an address, the
   * fingerprint or the owner, whose callback then gets the reading the check found. The owner
   * beside 24 stated words is rejected with LENGTH_DIFFERS too when one 12- to 21-word length
   * passes its check: only an address or the fingerprint tells the two readings apart. A stated
   * 12- to 21-word length whose check fails while no other passes rejects with VERIFIER_MISMATCH,
   * whatever the confirmation.
   *
   * After AMBIGUOUS_LENGTH or LENGTH_DIFFERS, which come once the recovery's rounds are done,
   * `onConfirmAgain` is called, when given, with `{ error, ownerLengths }`: the refusal as an
   * MhfeError, and the lengths at which the owner may compare the phrase with their backup, empty
   * where only an address or the fingerprint confirms it. It returns another confirmation, which
   * is judged on the same recovery without the rounds again: `{ address, coin, path?,
   * passphrase? }`, `{ fingerprint, passphrase? }`, or `{ owner, words }` with `words` one of
   * `ownerLengths` (left out when there is only one); or null, which rejects with the refusal.
   * After AMBIGUOUS_LENGTH the owner states the length of the reading to compare; after
   * LENGTH_DIFFERS it is the stated one, and the owner callback gets the reading the check found.
   * The answer to `walletHasPassphrase` holds for every confirmation. Without `onConfirmAgain`,
   * and after every other refusal, the rekey ends: a page calls rekey() again, which recovers
   * again.
   *
   * `confirmation` is exactly one of `{ builtInCheck: true }`, `{ address, coin, path? }`,
   * `{ fingerprint }` or `{ owner: (check) => true | { passphrase } | Promise<...> }`
   * (readContainer().confirmationFor says which a length needs, "0" for detection). The wallet
   * check, 16 bits, never confirms a phrase to encrypt again. The owner callback receives
   * `{ phrase, words, statedWords?, fingerprintWithoutPassphrase, rehearsalNeedsPassphrase }` to
   * compare with the written backup, `statedWords` only where the built-in check found another
   * length than the one stated, which the page says first. Its yes is true, or, where
   * `rehearsalNeedsPassphrase` says so, `{ passphrase }` with the wallet's BIP39 passphrase, from
   * which the fingerprint the new container's rehearsal compares is made; anything else stops the
   * rekey with NOT_CONFIRMED_BY_OWNER. Resolves as encrypt does, with `walletCheck`, the 16-bit
   * wallet check of a recovered 24-word reading with the reference's passphrase or none (null for
   * other lengths), which every recovery reports and which never confirms a rekey, and
   * `rehearsal`, what the new container phrase is rehearsed with: `{ kind: "builtInCheck" }`,
   * `{ kind: "confirmingReference" }` (the address or fingerprint that confirmed it) or
   * `{ kind: "fingerprint", fingerprint }` where the owner confirmed it alone. Show it with the
   * result, as the specification requires that reference before the replacement is used.
   *
   * `walletHasPassphrase` is the user's answer whether the wallet has a BIP39 passphrase, which
   * the new container's keep list names. An address or a fingerprint compared with a non-empty
   * `passphrase` shows that it has one: there the answer may be left out, and false is refused.
   * Everywhere else it is required (INVALID_REQUEST without it): the built-in check and the owner
   * show nothing, and a reference without a passphrase matches the phrase's wallet without one,
   * which says nothing about funds under a passphrase, so it confirms only a wallet stated to have
   * none: true is refused, as such a wallet is compared with its passphrase. These refusals come
   * before the rekey worker runs its Argon2 known answer or rounds. The class's independent
   * startup self-check can already have run.
   * `passphrase` belongs only to an address or a fingerprint: a non-empty one with the built-in
   * check or the owner is a TypeError.
   * @param {OptionsOf<"rekey">} [options]
   */
  async rekey({
    container,
    words = 0,
    password,
    passwordRepair,
    pim = 0,
    memoryLevel = 0,
    newPassword,
    newPasswordRepeat,
    newPasswordRepair,
    newPim = 0,
    newMemoryLevel = 0,
    repairWordCount = 0,
    confirmation,
    passphrase = "",
    walletHasPassphrase,
    onProgress,
    onUnverified,
    onConfirmAgain,
  } = {}) {
    requireText(container, "container");
    if (walletHasPassphrase !== undefined) requireWalletPassphrase(walletHasPassphrase);
    requireWordCount(words);
    requireSettings(newPim, newMemoryLevel, true);
    requireRepairWordCount(repairWordCount);
    requireCallback(onUnverified, "onUnverified");
    requireCallback(onConfirmAgain, "onConfirmAgain");
    const [confirmKind, reference, coin, path, firstOwner] = describeConfirmation(confirmation);
    requirePassphraseFits(confirmKind, passphrase, REKEY_PASSPHRASE_REFERENCES);
    // The owner callback of the confirmation being judged: an answer of onConfirmAgain may give
    // another.
    let owner = firstOwner;
    const [choice, position] = describeChoice(passwordRepair, "passwordRepair");
    const [newChoice, newPosition] = describeChoice(newPasswordRepair, "newPasswordRepair");
    const request = {
      operation: "rekey",
      container,
      words,
      choice,
      position,
      newChoice,
      newPosition,
      newPim,
      newMemoryLevel,
      repairWordCount,
      confirmKind,
      reference,
      coin,
      path,
      walletHasPassphrase,
      confirmsAgain: onConfirmAgain !== undefined,
    };
    /** @type {WorkerHandlers} */
    const handlers = {
      unverified: onUnverified,
      ownerCheck: (/** @type {OwnerCheck} */ check) => {
        if (owner === undefined) {
          throw packageMismatch("The worker asked the owner without an owner confirmation");
        }
        return answerOwner(owner, check);
      },
    };
    if (onConfirmAgain !== undefined) {
      handlers.confirmAgain = (/** @type {ConfirmAgainRefusal} */ refusal) =>
        answerConfirmAgain(onConfirmAgain, refusal, (/** @type {PageOwner} */ next) => {
          owner = next;
        });
    }
    return this.#runtime.long(request, {
      password,
      pim,
      memoryLevel,
      onProgress,
      passphrase,
      newPassword,
      newPasswordRepeat,
      handlers,
    });
  }
}
