import type {
  MhfePackageParts,
  MhfeSecret,
  MhfeSelfCheckProgress,
  MhfeSelfCheckReport,
} from "../runtime/runtime.js";
export {
  MhfeCancelledError,
  MhfeError,
  type MhfeErrorCode,
  type MhfeSelfCheckProgress,
  type MhfeSelfCheckReport,
} from "../runtime/runtime.js";

/** runtime/worker.js and runtime/mhfe.wasm. */
export type MhfeWalletSources = MhfePackageParts;

export interface MhfeNewPhrase {
  phrase: string;
  words: 24;
  /** Whether it was drawn to pass the wallet check with the passphrase. */
  walletCheck: boolean;
  /** The master key fingerprint with the passphrase given, which may be empty. */
  fingerprintWithPassphrase: string;
  /** How many workers drew it. */
  workers: number;
}

/** Every method returns a promise and reports every error by rejecting it; cancel() is synchronous. */
export class MhfeWallet {
  constructor(sources: MhfeWalletSources);
  /**
   * The quick self-check, made once per page and awaited by every other method but parameters() and cancel() before its first
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
    coins: { id: string; name: string; addressForms: string }[];
    walletCheckBits: number;
    drawReportInterval: number;
  }>;
  /** A 24-word phrase and a passphrase that is not empty; otherwise refused. */
  walletCheck(options: { phrase: string; passphrase: MhfeSecret }): Promise<boolean>;
  fingerprint(options: { phrase: string; passphrase?: MhfeSecret }): Promise<string>;
  /** `coin` is required: an id of parameters().coins. */
  describeAddress(options: { address: string; coin: string; path?: string }): Promise<{
    /** The address type, such as "native SegWit (BIP84)", when the coin has several. */
    type: string | null;
    /** The path pattern searched, or the one path given. */
    search: string;
    addresses: number;
    onlyPath: boolean;
  }>;
  /**
   * With a passphrase, typed twice, `walletCheck` must be given: never preselected. A checked
   * phrase takes about 65,536 draws, spread over `workers` workers.
   */
  drawPhrase(options?: {
    passphrase?: MhfeSecret;
    passphraseRepeat?: MhfeSecret;
    walletCheck?: boolean;
    workers?: number;
    onProgress?: (progress: { stage: "draw"; draws: number }) => void | Promise<void>;
  }): Promise<MhfeNewPhrase>;
  cancel(): void;
}
