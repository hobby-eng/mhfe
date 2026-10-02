# Next release notes — draft

Record user-visible changes here as they are made. Before tagging, move them into
`docs/releases/v<version>.md`: the release workflow publishes that file as the release text and
stops at once if it is missing.

- One program for every x86-64 computer instead of two. It uses SSSE3, 7 to 10% faster, where the
  processor has it and SSE2 otherwise, so the separate `ssse3` archives and the "processor not
  supported" refusal (`PROCESSOR_NOT_SUPPORTED`, exit code 4) are gone.
