import type {
  MhfePackageParts,
  MhfePasswordRepair,
  MhfeSecret,
  MhfeSelfCheckProgress,
  MhfeSelfCheckReport,
} from "../runtime/runtime.js";
export {
  MhfeError,
  type MhfeErrorCode,
  type MhfeSelfCheckProgress,
  type MhfeSelfCheckReport,
} from "../runtime/runtime.js";

/** runtime/worker.js and runtime/mhfe.wasm. */
export type MhfePasswordsSources = MhfePackageParts;

export interface MhfePasswordReview {
  profile: "MHFE-PASSWORD-CHECK-1";
  reading: "notThisShape" | "fits" | "restorable" | "mismatch";
  /** How the reviewed written form differs from the text typed; null when it does not. */
  correction: "extraSpaces" | "capitals" | "spacesAndCapitals" | null;
  correctionText: string | null;
  /** Whether "corrected" is a choice: a written form that fits as it is. */
  offersCorrection: boolean;
  /** Whether the repairs or the correction come before "as typed" among the answers. */
  repairsFirst: boolean;
  /** One for a restorable word, six for a mismatch; `typed` is null for a restored word. */
  repairs: { position: number; word: string; typed: string | null }[];
}

/** Every method returns a promise and reports every error by rejecting it. */
export class MhfePasswords {
  constructor(sources: MhfePasswordsSources);
  /**
   * The quick self-check, made once per page and awaited by every other method but parameters() before its first
   * call: known answers of each part the class computes, each with a case it must refuse. A failed
   * part closes the class for good: every such method then rejects with SELF_CHECK_FAILED, the
   * report attached. A page awaits it before it enables any field and shows the report on failure.
   */
  startupCheck(): Promise<MhfeSelfCheckReport>;
  /** The full self-check, run anew each time, in seconds; a failed part closes the class too. */
  fullCheck(options?: {
    onProgress?: (progress: MhfeSelfCheckProgress) => void | Promise<void>;
  }): Promise<MhfeSelfCheckReport>;
  parameters(): Promise<{
    version: string;
    checkWordProfile: "MHFE-PASSWORD-CHECK-1";
    defaultWords: number;
    recommendedWords: number;
    mostWords: number;
    defaultCharacters: number;
    recommendedCharacters: number;
    mostCharacters: number;
    weakBelowBits: number;
  }>;
  /**
   * With `passwordRepeat`, a new password typed twice: a difference, an empty repetition included,
   * is PASSWORDS_DIFFER.
   */
  review(options: {
    password: MhfeSecret;
    passwordRepeat?: MhfeSecret;
  }): Promise<MhfePasswordReview>;
  strength(options: {
    password: MhfeSecret;
    passwordRepair?: MhfePasswordRepair;
  }): Promise<{ bits: number; weak: boolean }>;
  /**
   * `count`: words (1 to 32, by default 5) or characters (1 to 64, by default 16). "checkWord"
   * always gives five words and their check word and takes no `count`: one given is a TypeError,
   * as `mhfe password` refuses `--check-word` with `--words`. `dice`: five digits from 1 to 6 per
   * word, separated by spaces; empty for the browser's randomness.
   */
  make(
    options?:
      | { kind?: "words" | "characters"; count?: number; dice?: MhfeSecret }
      | { kind: "checkWord"; count?: never; dice?: MhfeSecret },
  ): Promise<{ password: string; bits: number; weak: boolean; checkWord: boolean }>;
}
