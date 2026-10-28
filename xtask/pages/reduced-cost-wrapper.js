{
  const fullCostArgon2For = argon2For;
  const encoder = new TextEncoder();
  const faultyCheckPassword = encoder.encode(${inline(FAULTY_CHECK_PASSWORD)});
  const memoryFailurePassword = encoder.encode(${inline(MEMORY_FAILURE_PASSWORD)});
  const sameBytes = (bytes, other) =>
    bytes.length === other.length && bytes.every((byte, index) => byte === other[index]);
  const memoryFailure = () =>
    new Error("MEMORY_ALLOCATION_FAILED: the browser could not provide the Argon2 memory");
  // The costs of the builds' known answers (src/engine/known_answers.rs), which reach the build.
  const knownAnswerCosts = ["1024/1", "65536/3", "262144/2"];
  argon2For = async (request) => {
    const engine = await fullCostArgon2For(request);
    let calls = 0;
    return {
      derive(password, salt, memoryKib, passes, key) {
        if (knownAnswerCosts.includes(memoryKib + "/" + passes)) {
          return engine.derive(password, salt, memoryKib, passes, key);
        }
        if (memoryKib !== 2097152 || passes !== 12) {
          throw new Error(
            "TEST_COST: the core asked for " + memoryKib + " KiB and " + passes + " passes",
          );
        }
        if (sameBytes(password, memoryFailurePassword)) throw memoryFailure();
        engine.derive(password, salt, 256, 1, key);
        calls += 1;
        if (sameBytes(password, faultyCheckPassword) && calls > 12) key[0] ^= 1;
      },
      reserve(memoryKib) {
        if (memoryKib !== 2097152) throw new Error("TEST_COST: the core did not reserve 2 GiB");
        if (request.container === ${inline(MEMORY_FAILURE_CONTAINER)}) throw memoryFailure();
        return engine.reserve(256);
      },
    };
  };
}
