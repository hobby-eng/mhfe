async function checkRuntime(client, passwords, wallet, compiled) {
  group("Runtime");
  await expectRejection(
    new MhfeRepair({
      workerSource: WORKER_SOURCE,
      wasm: new Uint8Array([0, 97, 115, 109]),
    }).parameters(),
    "WORKER_FAILED",
    "WebAssembly that does not compile rejects with WORKER_FAILED",
  );
  await expectRejection(
    new MhfeRepair({ workerSource: "this is not JavaScript (", wasm: compiled }).parameters(),
    "WORKER_FAILED",
    "a worker whose script does not parse rejects with WORKER_FAILED",
  );
  await expectRejection(
    new MhfePasswords({
      workerSource: 'throw new Error("stopped");',
      wasm: compiled,
    }).parameters(),
    "WORKER_FAILED",
    "a worker whose script throws rejects with WORKER_FAILED",
  );
  await expectRejection(
    client.encrypt({
      phrase: PHRASE,
      password: "a\uD800",
      passwordRepeat: "a\uD800",
      walletHasPassphrase: false,
    }),
    "INVALID_PASSWORD_TEXT",
    "a password with an unpaired surrogate is refused",
  );
  await expectRejection(
    new MhfePasswords({ workerSource: WORKER_SOURCE, wasm: compiled }).review({
      password: "\uDC00 test",
    }),
    "INVALID_PASSWORD_TEXT",
    "the passwords module refuses an unpaired surrogate too",
  );
  expect(
    (await client.readPhrase(PHRASE)).phrase === PHRASE,
    "the client works after workers that failed",
  );

  // The client's own byte copies of secrets, seen through the page's TextEncoder, must be wiped
  // when an operation cannot start: here the browser refuses the worker's Blob URL.
  const copies = [];
  const RealTextEncoder = globalThis.TextEncoder;
  globalThis.TextEncoder = class extends RealTextEncoder {
    encode(text) {
      const encoded = super.encode(text);
      if (text === PASSWORD || text === "TREZOR") copies.push(encoded);
      return encoded;
    }
  };
  const realCreateObjectURL = URL.createObjectURL;
  const wiped = () => copies.every((copy) => copy.every((byte) => byte === 0));
  try {
    URL.createObjectURL = () => {
      throw new Error("refused by the page");
    };
    const refusedCheck = () =>
      client.check({
        container: REDUCED_COST_CONTAINER,
        password: PASSWORD,
        reference: { fingerprint: FINGERPRINT },
        passphrase: "TREZOR",
      });
    await expectRejection(
      refusedCheck(),
      "WORKER_FAILED",
      "a Blob URL the browser refuses rejects with WORKER_FAILED",
    );
    await expectRejection(
      refusedCheck(),
      "WORKER_FAILED",
      "the refused operation freed its slot: the next is not BUSY",
    );
    URL.createObjectURL = realCreateObjectURL;
    expect(
      copies.length === 4 && wiped(),
      "the copies of the password and the passphrase were wiped",
    );
    copies.length = 0;
    await expectTypeError(
      passwords.review({ password: PASSWORD, passwordRepeat: 5 }),
      "repeated password must be a string or a Uint8Array.",
      "a repetition that is not text is refused",
    );
    await expectRejection(
      wallet.drawPhrase({ passphrase: "TREZOR", passphraseRepeat: "\uD800", walletCheck: true }),
      "INVALID_PASSWORD_TEXT",
      "a passphrase repetition with an unpaired surrogate is refused",
    );
    // A repetition of the wrong type is refused before anything is copied (AUD-016-API003);
    // the unpaired surrogate is refused after the passphrase was copied, and that copy is wiped.
    expect(
      copies.length === 1 && wiped(),
      "the first entry's copy is wiped when its repetition is refused",
    );
  } finally {
    URL.createObjectURL = realCreateObjectURL;
    globalThis.TextEncoder = RealTextEncoder;
  }
}

function bytes(base64) {
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}
