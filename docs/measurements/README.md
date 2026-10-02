# Measurements

Timings from the author's laptop. They show what to expect, not what every computer does, and they
are not estimates of an attacker's cost. `mhfe test-benchmark` makes the same measurement on any
computer.

- [`full-operation-2026-09-30.json`](full-operation-2026-09-30.json): whole operations at the
  defaults, each measured from start to end rather than worked out from single Argon2 calls. On the
  command line a recovery took 67 to 72 seconds and an encryption with its check 2 to 2.3 minutes;
  the SSSE3 code, then a separate build, was 7 to 10 percent faster than the SSE2 code. In
  Chromium's fast mode a recovery took 90 to 95 seconds and an encryption 2.7 to 2.8 minutes; in the
  standard mode of a page opened as a file a recovery took about 4 minutes and an encryption about
  7.7 to 8 minutes.
- [`c-engine-2026-09-29.json`](c-engine-2026-09-29.json): suite 3 with the reference C Argon2
  engine. One Argon2id call at the default 2 GiB and 12 passes took 4.6 to 5.0 seconds natively with
  four threads, 5.7 seconds in Chromium's fast mode and about 19 seconds in the standard,
  single-threaded mode. A full operation of twelve calls took 73 to 90 seconds on the command line
  and 99 to 111 seconds in the browser's fast mode. The file also keeps an earlier, slower series
  from the same day and the findings that led to the C engine.
- `local-pim-0.json`, `local-pim-1.json` and `local-browser-pim-0.json` are the records of suite 2
  (512 MiB) with the former Rust Argon2 engine, kept for history.
