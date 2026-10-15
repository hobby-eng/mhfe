// The runtime as the class files of web/ see it in the type check (web/tsconfig.json), never
// shipped. In the package each class file imports "../runtime/runtime.js", which TypeScript reads
// from runtime/runtime.d.ts beside it: the public declarations. The class files also import the
// runtime's internal parts (WorkerJob, ModuleWorker, encodeSecret, ...), which that declaration
// leaves out, so here the import gives both: the declaration for the public types, and
// web/runtime.js with the types of its JSDoc for everything it exports.

export * from "../../runtime.js";
export * from "#runtime-script";
export type * from "../runtime-shared.d.ts";

import { MhfeModuleClass as ScriptModuleClass } from "#runtime-script";

// Exported by both: the classes and the constant as runtime.js has them, whose methods and
// constructors the class files call.
export {
  BUILD_ID,
  CompiledModule,
  MhfeCancelledError,
  MhfeError,
  PackageCheck,
} from "#runtime-script";

/**
 * The base class of runtime.js with the type parameter of its declaration, which the module
 * declarations (web/repair.d.ts and the others) give: runtime.js relays the worker's answer to
 * parameters() as it arrives, and the declaration names its type.
 */
export declare class MhfeModuleClass<Parameters> extends ScriptModuleClass {
  parameters(): Promise<Parameters>;
}
