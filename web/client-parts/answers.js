// @ts-check
/** @import { MhfeCheckEvidence, WordCount } from "../client.d.ts" */
/** @import { ConfirmAgainRefusal, OwnerCheck, PageOwner, PageAnswer } from "../types/client-shared.d.ts" */
import {
  requirePassphraseFits,
  REKEY_PASSPHRASE_REFERENCES,
  describeReference,
  CHECK_PASSPHRASE_REFERENCES,
  describeConfirmation,
} from "./references.js";
import { NO_LENGTH_FORMS } from "./values.js";
import { encodeSecret, askPage, MhfeError, sentence, countsText } from "../../runtime/runtime.js";

/**
 * The owner's answer to the phrase shown in a rekey: true, or `{ passphrase }` with the wallet's
 * BIP39 passphrase for the rehearsal's fingerprint, sent to the worker as a secret. Anything else
 * is a no.
 * @param {PageOwner} owner
 * @param {OwnerCheck} check
 */
export async function answerOwner(owner, check) {
  const answer = await owner(check);
  const withPassphrase = isPassphraseAnswer(answer);
  if (withPassphrase && !check.rehearsalNeedsPassphrase) {
    requirePassphraseFits("owner", answer.passphrase, REKEY_PASSPHRASE_REFERENCES);
  }
  // A passphrase answered is checked as any other: null is a TypeError, not an empty passphrase.
  const message = {
    confirmed: answer === true || withPassphrase,
    passphrase: encodeSecret(withPassphrase ? answer.passphrase : "", "passphrase"),
  };
  return { message };
}

/**
 * Whether the owner's answer is the yes with the wallet's passphrase, `{ passphrase }`: an object
 * whose only key with a value is passphrase. Any other key is refused rather than read, as
 * `{ confirmed: false, passphrase }` would otherwise seal the phrase the owner rejected
 * (AUD-024-API001); an object with no key is a no, as every answer but true.
 * @param {unknown} answer
 * @returns {answer is { passphrase: unknown }}
 */
export function isPassphraseAnswer(answer) {
  if (typeof answer !== "object" || answer === null) return false;
  const keys = Object.entries(answer)
    .filter(([, value]) => value !== undefined)
    .map(([key]) => key);
  if (keys.length === 0) return false;
  if (keys.length === 1 && keys[0] === "passphrase") return true;
  throw new TypeError(
    `The owner callback gives true, false or { passphrase }, not an object with ${keys.join(", ")}.`,
  );
}

/** What onNoLength may give instead of detection, which found no verified length. */
export const NO_LENGTH_ANSWERS = "a length, an address or a fingerprint";

/**
 * The page's answer when detection found no verified length (check's onNoLength), told what
 * detection found: another reference with its passphrase, sent to the worker as a secret, or null.
 * The answer is checked as a reference is; detection again is refused.
 * @param {(evidence: MhfeCheckEvidence) => PageAnswer | PromiseLike<PageAnswer>} onNoLength
 * @param {MhfeCheckEvidence} evidence
 */
export async function answerNoLength(onNoLength, evidence) {
  const answer = await askPage(onNoLength, evidence, "onNoLength");
  if (answer === null || answer === undefined) return null;
  const { passphrase = "", ...reference } = answer;
  // Deliberate copy: early refusal of RecoveredForCheck::compare_after_detection; package
  // follow-up checks exercise the class and the binding with the same forbidden references.
  if (reference.words === 0) {
    throw new TypeError(`onNoLength gives ${NO_LENGTH_ANSWERS}, not detection again.`);
  }
  // The wallet check (16 bits) tells a right password from a wrong one, not which length or
  // wallet it is: the check already reports it beside a reading that is not verified.
  if (reference.walletCheck !== undefined) {
    throw new TypeError(`onNoLength gives ${NO_LENGTH_ANSWERS}, not the wallet check.`);
  }
  const [referenceKind, value, coin, path] = describeReference(
    reference,
    "onNoLength",
    NO_LENGTH_FORMS,
  );
  requirePassphraseFits(referenceKind, passphrase, CHECK_PASSPHRASE_REFERENCES);
  const message = {
    referenceKind,
    reference: value,
    coin,
    path,
    passphrase: encodeSecret(passphrase, "passphrase"),
  };
  return { message };
}

/**
 * The page's answer when a rekey's confirmation is refused and another may follow on the same
 * recovery (rekey()'s onConfirmAgain): another confirmation, sent to the worker with its
 * passphrase as a secret, or null. The answer is checked as rekey() checks its confirmation; the
 * owner states `words`, one of `ownerLengths`. `useOwner` takes the callback of an owner's answer.
 * @param {(refusal: { error: MhfeError, ownerLengths: WordCount[] }) =>
 *   PageAnswer | PromiseLike<PageAnswer>} onConfirmAgain
 * @param {ConfirmAgainRefusal} refusal
 * @param {(owner: PageOwner) => void} useOwner
 */
export async function answerConfirmAgain(
  onConfirmAgain,
  { code, message, ownerLengths },
  useOwner,
) {
  const answer = await askPage(
    onConfirmAgain,
    { error: new MhfeError(code, sentence(message)), ownerLengths: [...ownerLengths] },
    "onConfirmAgain",
  );
  if (answer === null || answer === undefined) return null;
  const { passphrase = "", words, ...confirmation } = answer;
  const [confirmKind, reference, coin, path, owner] = describeConfirmation(confirmation);
  requirePassphraseFits(confirmKind, passphrase, REKEY_PASSPHRASE_REFERENCES);
  /** @type {unknown} */
  let stated = 0;
  if (owner !== undefined) {
    stated = words ?? (ownerLengths.length === 1 ? ownerLengths[0] : undefined);
    // Deliberate copy: Rekey::owner_states owns this rule. Package follow-up checks bind
    // the early class refusal to the library's allowed ownerLengths and default selection.
    if (!ownerLengths.some((length) => length === stated)) {
      throw new TypeError(
        ownerLengths.length === 0
          ? "the owner cannot confirm this phrase: give an address or the fingerprint."
          : `words must name the reading the owner compares: ${countsText(ownerLengths)}.`,
      );
    }
    useOwner(owner);
  } else if (words !== undefined) {
    throw new TypeError("words belongs only to the owner's confirmation.");
  }
  const next = {
    confirmKind,
    reference,
    coin,
    path,
    words: stated,
    passphrase: encodeSecret(passphrase, "passphrase"),
  };
  return { message: next };
}
