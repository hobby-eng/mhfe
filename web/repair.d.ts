import type {
  MhfePackageParts,
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
export type MhfeRepairSources = MhfePackageParts;

export interface MhfeRepairCard {
  profile: "MHFE-REPAIR-1";
  /** The repair words, one space apart. */
  words: string;
  /** Unreadable words the card repairs. */
  repairsUnreadable: number;
  /** Wrong words the card repairs: half as many. */
  repairsWrong: number;
}

export interface MhfeRepaired {
  /** The repaired container, every word in full. */
  container: string;
  containerFingerprint: string;
  /** True when nothing needed a repair. */
  unchanged: boolean;
  /** Positions of the plate's words that were repaired, from 1. */
  plateWords: number[];
  /** Positions of the card's words that were wrong or unreadable, from 1. */
  cardWords: number[];
  /** Every repaired word with what was read there, plate first: a repair is never silent. */
  changes: { onCard: boolean; position: number; read: string | null; word: string }[];
}

/** Every method returns a promise and reports every error by rejecting it. */
export class MhfeRepair {
  constructor(sources: MhfeRepairSources);
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
    profile: "MHFE-REPAIR-1";
    repairWordCounts: (2 | 4 | 6 | 8)[];
    recommendedRepairWords: number;
    repairCapacities: { count: number; unreadable: number; wrong: number }[];
  }>;
  repairWords(options: { container: string; count: 2 | 4 | 6 | 8 }): Promise<MhfeRepairCard>;
  /** "?" stands for a word that cannot be read. */
  repairPlate(options: { plate: string; card: string }): Promise<MhfeRepaired>;
}
