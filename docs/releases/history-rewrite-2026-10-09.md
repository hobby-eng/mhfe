# Release commits before and after the history rewrites of 2026-10-09

On 2026-10-09 the history of this repository was rewritten twice, to remove private metadata from
audit documents and commit headers. The first rewrite removed home-directory paths, location
annotations and local times. The second removed the PATH values of recorded command environments,
the last local clock times, the time-of-day keys of a measurement and one source comment, and it
replaced the commit address with the GitHub no-reply address. Every commit got a new hash each time.
The release tags were moved to the rewritten commits and signed again, with their original dates
and messages.

The release files of v0.3.0, v0.4.0 and v0.5.0 were built before the rewrites, from the original
commits. Their build provenance (`gh attestation verify`) therefore names an original commit, which
this repository no longer contains. The table pairs each original commit with the commit its tag
names now (AUD-015-BLD001).

| Release | Built from (original commit)               | Tagged now (rewritten commit)              | Tag object                                 |
| ------- | ------------------------------------------ | ------------------------------------------ | ------------------------------------------ |
| v0.3.0  | `1f18322dbc23df54b10719efb0113fcd4ba88242` | `cf0defcfff1f5795ec0d1f16b2d82cd0efe07a8c` | `bf689dd597a386f6db46e5d273f9ae7fcde0f57a` |
| v0.4.0  | `70dddd069b3e3bb6553a3a41c42713d1e09f2d87` | `e1c0c8f1e70246e49cac3d0510f6ce6c758c4d6e` | `88b8ff9921c8a9a9b6805f9772df4e3d0798d151` |
| v0.5.0  | `52b6b36a16d36fa895f3b3e9e034b52c9f963c34` | `dd439751ca992535e726b7c1d5d77b410371d673` | `417edebf31ae66e13ce6f62b0535028ee08a93a4` |

According to the rewrites' own records, each rewritten commit has the same files as its original
except audit documents under `docs/audits/`, a measurement file and one comment in
`src/bin/mhfe/hidden_input.rs`. No other source file, build script, lock file or test vector
changed.

The release files themselves did not change. `SHA256SUMS` and its OpenPGP signature still verify
them as before, and the build provenance still names the workflow run that built them. To connect
that run with the current history, look up its commit in the table above.
