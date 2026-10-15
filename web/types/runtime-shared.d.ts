// Source-only types shared by the page modules; public contracts stay in the package declarations.
import type {
  MhfeComponentResult,
  MhfeSelfCheckProgress,
  PackageCheck as DeclaredPackageCheck,
} from "../runtime.d.ts";

/** A request to the worker: its module, its operation and that operation's fields, the secrets
among them as SecretBytes owners; or a later message of the same operation. */
export type WorkerRequest = Record<string, unknown>;

/** The answer to a worker's question: the job takes ownership of `message` and transfers its
secret buffers; null or undefined answers nothing. It is no promise (`then`), so that callPage
tells it from one. */
export type WorkerAnswer = { message: unknown; then?: undefined } | null | undefined;

/** What a page's handler of a worker's message gives: nothing or a promise for news, whose promise
is not awaited, and the answer or its promise for a question. */
export type HandlerResult = void | WorkerAnswer | PromiseLike<void | WorkerAnswer>;

/** A page's handler of one type of message of a worker, news such as "progress" or a question. It
takes the message's value as the worker sends it for that type (web/worker-runtime.js and the
module workers), so an inline handler names that type on its parameter. */
export type WorkerHandler = (value: never) => HandlerResult;

/** A WorkerHandler as a worker's message calls it, with the value as it arrived. WorkerJob calls a
handler only after isReadableReply has read the envelope, the build handshake has succeeded,
and readWorkerValue has validated this channel's payload. The checkedPageHandler adapter
keeps the heterogeneous handler assertion inside that validated protocol reader. */
export type ArrivedHandler = (value: unknown) => HandlerResult;

export type WorkerHandlers = { [type: string]: WorkerHandler | undefined };

/** A message of the worker once isReadableReply has checked that it can be read. */
export type WorkerReply = { type: string; [field: string]: unknown };

/** What a class's set of known answers gives from its worker (`selfCheck` in
web/worker-runtime.js): the release version, the parts that ran, and `ids`, the order of the
whole set, parts left out included; a WebAssembly that stopped gives no order. */
export type SetReport = {
  version: string | null;
  components: MhfeComponentResult[];
  ids?: string[];
};

/** Runs a class's set of known answers in a worker, without the parts `skip`, its news going to
`handlers`; resolves to the worker's SetReport. */
export type RunSet = (skip: string[], handlers: WorkerHandlers) => Promise<unknown>;

/** Names a part of a self-check in a class's report, as it starts and as it ends. */
export type RenamePart = <Part extends { id: string; label: string }>(part: Part) => Part;

/** A step of a self-check (PackageCheck.full): a set run in a worker, `rename` naming its parts in
the report and `skipPassed` leaving out those another class passed; or parts not run here. */
export type CheckStep =
  | { run: RunSet; rename?: RenamePart; skipPassed?: boolean; components?: undefined }
  | { components: MhfeComponentResult[] };

/** The callback that hears of each part of a self-check as it starts and ends. */
export type SelfCheckListener = (progress: MhfeSelfCheckProgress) => void | Promise<void>;

export type PackageCheckOptions = ConstructorParameters<typeof DeclaredPackageCheck>[0];
