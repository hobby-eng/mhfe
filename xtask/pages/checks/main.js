async function main() {
  // The core takes the package's WebAssembly as bytes; the other classes share one compiled
  // module, as a page that uses several classes does.
  const client = new MhfeClient({
    workerSource: WORKER_SOURCE,
    wasm: bytes(WASM_BASE64),
    argon2Threaded: ARGON2_THREADED,
    argon2SingleThreaded: ARGON2_SINGLE_THREADED,
  });
  const compiled = await WebAssembly.compile(bytes(WASM_BASE64));
  const repair = new MhfeRepair({ workerSource: WORKER_SOURCE, wasm: compiled });
  const passwords = new MhfePasswords({ workerSource: WORKER_SOURCE, wasm: compiled });
  const wallet = new MhfeWallet({ workerSource: WORKER_SOURCE, wasm: compiled });
  // Containers the encryption checks make, for the checks of the other methods.
  const made = {};

  await checkStartupChecks(client, repair, passwords, wallet);
  await checkConstruction(client, compiled);
  await checkReading(client);
  await checkEncrypt(client, repair, made);
  await checkDecrypt(client, wallet, made);
  await checkRehearsal(client, made);
  await checkCancelAndCallbacks(client);
  await checkMemoryFailures(client);
  await checkRekey(client, repair, wallet, made);
  await checkHiddenWallets(client, wallet, made);
  await checkSelfTest(client);
  await checkFullChecks(client, repair, passwords, wallet);
  await checkFailingSelfCheck(compiled);
  await checkArgon2Start();
  await checkRepair(repair);
  await checkPasswords(passwords);
  await checkWallet(wallet);
  await checkRuntime(client, passwords, wallet, compiled);
  return client.mode();
}
