# TODO

## Future mobile applications

These tasks are deferred until the current remediation and verification work is complete.

- [ ] Establish Android and iOS memory feasibility before implementing either application. On
      real devices, measure whether the operating system permits the 2 GiB Argon2 work area at
      `PIM=0, MEM=0`, together with application overhead. Check process memory limits, pressure,
      suspension and termination, using public test vectors and the unchanged production cost.
- [ ] Create an Android APK using the existing Rust core, with Android bindings and a mobile
      interface. Include ARM64 device tests, secret handling, cancellation and lifecycle checks;
      preserve the existing formats, settings and deterministic outputs.
- [ ] Consider an optional iOS application after the memory-feasibility investigation. Record
      supported devices and operating-system restrictions before deciding whether to proceed.

## Related mobile work

- [ ] Coordinate a future Android application for MnemoCode after its planned Rust port. Reuse
      its Rust core and assess Android memory and lifecycle restrictions before implementation.
