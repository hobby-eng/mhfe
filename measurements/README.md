# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics — Local Measurements

Measurement files are non-normative observations from one machine. They are
not test vectors, performance guarantees, or attack-cost estimates. Regenerate
them on each target system with the `benchmark` command.

`local-pim-0.json` records the first native observation for experimental suite 2 on the
Samsung `NP950QED-KA2DE` development machine. It was produced by the vector command under
`/usr/bin/time`; it is not part of the interoperable test vector.

`local-pim-1.json` records the corresponding non-default-PIM round trip, an independent
forward-round recalculation, and a wrong-PIM verifier-rejection check on the same machine.

`local-browser-pim-0.json` records a complete Chromium module-Worker/WASM round trip against the
published PIM-0 container and checks the reduced browser-result surface.
