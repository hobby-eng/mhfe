export interface MhfeSuiteParameters {
  apiVersion: number;
  suiteId: string;
  roundCount: number;
  memoryKib: number;
  basePasses: number;
  lanes: number;
  maxPim: number;
  supportedSourceWords: readonly [12, 15, 18, 21, 24];
  passwordNormalization: string;
}

export interface MhfeEncryptionResult {
  apiVersion: number;
  suiteId: string;
  pim: number;
  effectivePasses: number;
  sourceWords: 12 | 15 | 18 | 21 | 24;
  encryptedMnemonic: string;
}

export interface MhfeDecryptionResult {
  apiVersion: number;
  suiteId: string;
  pim: number;
  effectivePasses: number;
  sourceWords: 12 | 15 | 18 | 21 | 24;
  recoveredMnemonic: string;
  recoveryVerifier: 'matched' | 'unavailable';
}

export class MhfeWorkerError extends Error {
  readonly code: string;
  constructor(code: string, message: string);
}

export class MhfeCancelledError extends Error {
  constructor(message?: string);
}

export class MhfeWorkerClient {
  static fromUrl(url: string | URL, wasmModuleOrBytes: MhfeWasmInput): MhfeWorkerClient;
  constructor(worker: Worker, wasmModuleOrBytes: MhfeWasmInput);
  ready(): Promise<MhfeSuiteParameters>;
  parameters(): Promise<MhfeSuiteParameters>;
  encryptAscii(mnemonic: string, passwordAscii: string, pim?: number): Promise<MhfeEncryptionResult>;
  decryptAscii(
    container: string,
    sourceWords: 12 | 15 | 18 | 21 | 24,
    passwordAscii: string,
    pim?: number,
  ): Promise<MhfeDecryptionResult>;
  decryptAsciiAuto(
    container: string,
    passwordAscii: string,
    pim?: number,
  ): Promise<MhfeDecryptionResult>;
  encryptPreNormalizedUtf8(
    mnemonic: string,
    passwordUtf8: Uint8Array,
    pim?: number,
  ): Promise<MhfeEncryptionResult>;
  decryptPreNormalizedUtf8(
    container: string,
    sourceWords: 12 | 15 | 18 | 21 | 24,
    passwordUtf8: Uint8Array,
    pim?: number,
  ): Promise<MhfeDecryptionResult>;
  decryptPreNormalizedUtf8Auto(
    container: string,
    passwordUtf8: Uint8Array,
    pim?: number,
  ): Promise<MhfeDecryptionResult>;
  disposeEngine(): Promise<null>;
  cancel(): void;
  terminate(reason?: Error): void;
}

export type MhfeWasmInput = WebAssembly.Module | Uint8Array | ArrayBuffer;
