// Source-only types shared by the page modules; public contracts stay in the package declarations.
import type {
  MhfeClient as DeclaredClient,
  MhfeConfirmation,
  MhfeHiddenWallets,
  MhfeProgress,
  WordCount,
} from "../client.d.ts";
import type { MhfeErrorCode } from "../runtime.d.ts";
import type { WorkerHandler, WorkerHandlers } from "./runtime-shared.d.ts";

/** The options of a method of the declaration, as a page may pass them: any may be missing or
wrong, and the method checks them. */
export type OptionsOf<Method extends keyof DeclaredClient> = Partial<
  NonNullable<Parameters<DeclaredClient[Method]>[0]>
>;

/** The options of a long operation (CoreRuntime.begin): its secrets as the page gave them, which #start checks
and copies into bytes, its settings, and the page's handlers of the worker's messages. */
export type LongOptions = {
  phrase?: unknown;
  password?: unknown;
  passwordRepeat?: unknown;
  passphrase?: unknown;
  newPassword?: unknown;
  newPasswordRepeat?: unknown;
  mainPassphrase?: unknown;
  pim?: number | undefined;
  memoryLevel?: number | undefined;
  onProgress?: WorkerHandler | undefined;
  handlers?: WorkerHandlers;
  noPassword?: boolean;
};

/** A refusal of the core as the worker sends it (describeError in web/worker-runtime.js). */
export type WorkerRefusal = { code: MhfeErrorCode; message: string };

/** A refusal of a rekey's confirmation after which another may follow on the same recovery, with
the lengths at which the owner may compare the phrase (recoverConfirmed in web/core-worker.js). */
export type ConfirmAgainRefusal = WorkerRefusal & { ownerLengths: WordCount[] };

export type OwnerCallback = Extract<MhfeConfirmation, { owner: unknown }>["owner"];
export type OwnerCheck = Parameters<OwnerCallback>[0];

/** The owner's callback of a confirmation as describeConfirmation() wraps it, which names its
failure CALLBACK_FAILED. */
export type PageOwner = (check: OwnerCheck) => Promise<Awaited<ReturnType<OwnerCallback>>>;

/** The confirmation of a rekey as the worker takes it: its kind, the reference, coin and path of
an address or a fingerprint, and the owner's callback. */
export type DescribedConfirmation = [
  kind: string,
  reference: string,
  coin: string,
  path: string,
  owner: PageOwner | undefined,
];

/** An answer of a page's callback, read as an object whose fields are checked here; the declared
answers are such objects. */
export type PageAnswer = Record<string, unknown> | null | undefined;

/** An open of a hidden wallet that waits for the worker's answer (openHiddenWallets). */
export type PendingOpen = {
  resolve: (wallet: unknown) => void;
  reject: (error: unknown) => void;
  onProgress: ((progress: MhfeProgress) => void | Promise<void>) | undefined;
};

/** A session of hidden wallets as openHiddenWallets() gives it: MhfeHiddenWallets of the
declaration, whose options a page may pass with any missing or wrong. */
export type HiddenWalletsHandle = {
  open(options?: Partial<Parameters<MhfeHiddenWallets["open"]>[0]>): Promise<unknown>;
  close(): Promise<void>;
};

/** The start of a session of hidden wallets, which resolves with its handle once the worker is
ready. */
export type SessionStart = {
  resolve: (handle: HiddenWalletsHandle | null) => void;
  reject: (error: unknown) => void;
};
