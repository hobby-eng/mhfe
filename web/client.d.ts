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

export interface MhfeCycleWalkProgress {
  direction: 'encrypt' | 'decrypt';
  iterations: number;
  targetFinalWordIndex: number;
  currentFinalWordIndex: number;
  matched: boolean;
}

export interface MhfeCycleWalkEncryptionResult {
  apiVersion: number;
  suiteId: string;
  profileId: string;
  pim: number;
  effectivePasses: number;
  sourceWords: 24;
  iterations: number;
  preservedFinalWord: string;
  encryptedMnemonic: string;
}

export interface MhfeCycleWalkDecryptionResult {
  apiVersion: number;
  suiteId: string;
  profileId: string;
  pim: number;
  effectivePasses: number;
  sourceWords: 24;
  iterations: number;
  preservedFinalWord: string;
  recoveredMnemonic: string;
}

export type MhfeCycleWalkProgressCallback = (progress: MhfeCycleWalkProgress) => void;

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
  encryptPreservingFinalWordAscii(
    mnemonic: string,
    passwordAscii: string,
    pim?: number,
    onProgress?: MhfeCycleWalkProgressCallback,
  ): Promise<MhfeCycleWalkEncryptionResult>;
  decryptAscii(
    container: string,
    sourceWords: 12 | 15 | 18 | 21 | 24,
    passwordAscii: string,
    pim?: number,
  ): Promise<MhfeDecryptionResult>;
  decryptPreservingFinalWordAscii(
    container: string,
    passwordAscii: string,
    pim?: number,
    onProgress?: MhfeCycleWalkProgressCallback,
  ): Promise<MhfeCycleWalkDecryptionResult>;
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
  encryptPreservingFinalWordPreNormalizedUtf8(
    mnemonic: string,
    passwordUtf8: Uint8Array,
    pim?: number,
    onProgress?: MhfeCycleWalkProgressCallback,
  ): Promise<MhfeCycleWalkEncryptionResult>;
  decryptPreNormalizedUtf8(
    container: string,
    sourceWords: 12 | 15 | 18 | 21 | 24,
    passwordUtf8: Uint8Array,
    pim?: number,
  ): Promise<MhfeDecryptionResult>;
  decryptPreservingFinalWordPreNormalizedUtf8(
    container: string,
    passwordUtf8: Uint8Array,
    pim?: number,
    onProgress?: MhfeCycleWalkProgressCallback,
  ): Promise<MhfeCycleWalkDecryptionResult>;
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
