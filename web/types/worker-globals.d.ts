// The globals that runtime/worker.js holds in front of the worker parts of web/, for the type
// check of those parts only (web/tsconfig.worker.json), never shipped: scripts/build-wasm.sh joins
// the wasm-bindgen glue of runtime/mhfe.wasm, whose global is `mhfe`, before them, and the core
// places one or both Emscripten builds of the reference Argon2 code in front of the worker. Only
// the members the worker parts use are declared, with the types the glue converts them to.

/** The object the Rust core calls once per round (src/engine/browser.rs, web/argon2-engine.js). */
interface Argon2Engine {
  /** Argon2id of `password` and `salt` into `key`, views into the Rust core's memory. */
  derive(
    password: Uint8Array,
    salt: Uint8Array,
    memoryKib: number,
    passes: number,
    key: Uint8Array,
  ): void;
  /** Grows the C heap to `memoryKib` once and frees it again. */
  reserve(memoryKib: number): void;
}

/** The random source of the page, which fills a view of the WebAssembly's memory in place. */
interface RandomSource {
  fill(bytes: Uint8Array<ArrayBuffer>): void;
}

/** Hears of each round as it starts: the round from 1, the rounds in all, and the stage. */
type RoundListener = (round: number, rounds: number, stage: string) => void;
/** Hears of a part of a self-check as it starts. */
type PartStartListener = (id: string, label: string) => void;
/** Hears of a part of a self-check as it ends, with its result as JSON. */
type PartResultListener = (json: string) => void;

/** The wasm-bindgen glue of runtime/mhfe.wasm. The functions that answer with JSON give text. */
declare namespace mhfe {
  /** Instantiates the compiled WebAssembly that the page passed. */
  function initSync(options: { module: WebAssembly.Module }): unknown;
  function packageVersion(): string;

  function suiteParameters(): string;
  function describePhrase(phrase: Uint8Array): string;
  function describeContainer(container: string): string;
  function encrypt(
    phrase: Uint8Array,
    password: Uint8Array,
    repeat: Uint8Array,
    choice: string,
    position: number,
    pim: number,
    memoryLevel: number,
    sameLength: boolean,
    repairWordCount: number,
    walletHasPassphrase: boolean | null | undefined,
    argon2: Argon2Engine,
    onRound: RoundListener,
    onUnverified: (json: string) => void,
  ): string;
  function decrypt(
    container: string,
    password: Uint8Array,
    choice: string,
    position: number,
    pim: number,
    memoryLevel: number,
    words: number,
    passphrase: Uint8Array,
    argon2: Argon2Engine,
    onRound: RoundListener,
  ): string;
  function searchCandidates(container: string): string;
  function keepOldContainer(pim: number, memoryLevel: number): string;
  function searchDecoy(
    container: string,
    referenceKind: string,
    reference: string,
    coin: string,
    path: string,
    passphrase: Uint8Array,
    scanGap: number,
    onCandidate: (candidate: number, candidates: number) => void,
  ): string;
  function searchWallet(
    container: string,
    password: Uint8Array,
    choice: string,
    position: number,
    pim: number,
    memoryLevel: number,
    referenceKind: string,
    reference: string,
    coin: string,
    path: string,
    passphrase: Uint8Array,
    argon2: Argon2Engine,
    onCandidate: (candidate: number, candidates: number) => void,
    onRound: RoundListener,
  ): string;
  function selfTest(argon2: Argon2Engine, onRound: RoundListener): string;
  function selfCheckCore(
    tier: string,
    skip: string[],
    argon2: Argon2Engine | undefined,
    onStart: PartStartListener,
    onResult: PartResultListener,
  ): string;
  function selfCheckProcess(
    tier: string,
    skip: string[],
    onStart: PartStartListener,
    onResult: PartResultListener,
  ): string;
  function selfCheckArgon2(
    tier: string,
    skip: string[],
    argon2: Argon2Engine,
    onStart: PartStartListener,
    onResult: PartResultListener,
  ): string;

  function repairParameters(): string;
  function repairWords(container: string, count: number): string;
  function repairContainer(container: string, card: string): string;
  function inspectContainer(container: string): string;
  function selfCheckRepair(
    tier: string,
    skip: string[],
    onStart: PartStartListener,
    onResult: PartResultListener,
  ): string;

  function passwordParameters(): string;
  function reviewPassword(password: Uint8Array, repeat: Uint8Array, repeated: boolean): string;
  function passwordStrength(password: Uint8Array, choice: string, position: number): string;
  function makePassword(
    kind: string,
    count: number | undefined,
    rolls: Uint8Array,
    random: RandomSource,
  ): string;
  function selfCheckPasswords(
    tier: string,
    skip: string[],
    random: RandomSource,
    onStart: PartStartListener,
    onResult: PartResultListener,
  ): string;

  /** The hint for a line of words typed so far, from the list "bip39" or "eff". */
  function wordHints(list: string, typed: Uint8Array): string;

  function walletParameters(): string;
  function walletCheck(phrase: Uint8Array, passphrase: Uint8Array): boolean;
  function walletFingerprint(phrase: Uint8Array, passphrase: Uint8Array): string;
  function describeAddress(address: string, coin: string, path: string, scanGap: number): string;
  function describeDraw(
    chosenWords: Uint8Array,
    places: Uint32Array,
    neverUse: string,
    walletCheck: boolean,
  ): string;
  function drawPhrase(
    passphrase: Uint8Array,
    passphraseRepeat: Uint8Array,
    chosenWords: Uint8Array,
    places: Uint32Array,
    neverUse: string,
    walletCheck: boolean,
    random: RandomSource,
    onDraws: (draws: number) => void,
  ): string;
  function selfCheckWallet(
    tier: string,
    skip: string[],
    random: RandomSource,
    onStart: PartStartListener,
    onResult: PartResultListener,
  ): string;

  /** A rehearsal check in one worker: the recovery once, then comparisons with references. */
  class CheckSession {
    constructor(
      container: string,
      password: Uint8Array,
      choice: string,
      position: number,
      pim: number,
      memoryLevel: number,
      referenceKind: string,
      reference: string,
      coin: string,
      path: string,
      passphrase: Uint8Array,
      argon2: Argon2Engine,
      onRound: RoundListener,
    );
    compare(
      referenceKind: string,
      reference: string,
      coin: string,
      path: string,
      passphrase: Uint8Array,
    ): string;
    free(): void;
  }

  /** A rekey in its order: settings, recovery and confirmation, the owner's answer, the seal. */
  class RekeySession {
    constructor(
      container: string,
      words: number,
      password: Uint8Array,
      choice: string,
      position: number,
      pim: number,
      memoryLevel: number,
      argon2: Argon2Engine,
    );
    setNew(
      password: Uint8Array,
      repeat: Uint8Array,
      choice: string,
      position: number,
      pim: number,
      memoryLevel: number,
      repairWordCount: number,
    ): void;
    recover(
      kind: string,
      reference: string,
      coin: string,
      path: string,
      passphrase: Uint8Array,
      walletHasPassphrase: boolean | null | undefined,
      onRound: RoundListener,
    ): string;
    confirmAgain(
      kind: string,
      reference: string,
      coin: string,
      path: string,
      passphrase: Uint8Array,
      words: number,
      onRound: RoundListener,
    ): string;
    ownerLengths(): string;
    ownerAnswer(confirmed: boolean, passphrase: Uint8Array): void;
    seal(onRound: RoundListener, onUnverified: (json: string) => void): string;
    free(): void;
  }

  /** A session of hidden wallets: one wallet for each password, on one reserved work area. */
  class HiddenWalletSession {
    constructor(
      container: string,
      pim: number,
      memoryLevel: number,
      mainPassphrase: Uint8Array,
      argon2: Argon2Engine,
    );
    open(
      password: Uint8Array,
      repeat: Uint8Array,
      choice: string,
      position: number,
      onRound: RoundListener,
    ): string;
    free(): void;
  }
}

/** An Emscripten build of the reference Argon2 code, as web/argon2-engine.js calls it. */
interface Argon2Module {
  /** A view of the C heap, replaced when the heap grows. */
  HEAPU8: Uint8Array;
  /** A pointer to `size` bytes of the C heap, 0 when there is no memory. */
  _malloc(size: number): number;
  _free(pointer: number): void;
  /** argon2id_hash_raw of vendor/phc-winner-argon2/include/argon2.h: 0, or an error code. */
  _argon2id_hash_raw(
    passes: number,
    memoryKib: number,
    lanes: number,
    password: number,
    passwordLength: number,
    salt: number,
    saltLength: number,
    key: number,
    keyLength: number,
  ): number;
}

/**
 * The factory an Argon2 build defines, which starts its WebAssembly; the lane workers of the
 * threaded build load `mainScriptUrlOrBlob`.
 */
type Argon2Factory = (options?: { mainScriptUrlOrBlob: Blob | null }) => Promise<Argon2Module>;

/** The factory of core/argon2-mt.js, when that build is in front of the worker. */
declare var createArgon2Mt: Argon2Factory | undefined;
/** The factory of core/argon2-st.js, when that build is in front of the worker. */
declare var createArgon2St: Argon2Factory | undefined;
/** The build of core/argon2-mt.js (scripts/build-wasm.sh), when it is in front of the worker. */
declare const ARGON2_THREADED_BUILD_ID: string | undefined;
/** The build of core/argon2-st.js (scripts/build-wasm.sh), when it is in front of the worker. */
declare const ARGON2_SINGLE_THREADED_BUILD_ID: string | undefined;
