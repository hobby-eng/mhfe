#!/usr/bin/env bash
# AUD-024 gap-1-aud023-observations-under-current-guide: the two-word decoy search with a master key
# fingerprint (src/search.rs). Computes the fingerprint of every one of the 262,144 candidates of
# "abandon" x10 + two missing words, finds the pairs that share a fingerprint, and runs
# ContainerSearch::search_decoy with the later candidate's fingerprint. Exits 1 when the search
# returns the other container. About 66 CPU-minutes (4.5 minutes on 16 cores). See README.md.
set -uo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
here="$root/docs/audits/AUD-024-harnesses/gap-1-aud023-observations-under-current-guide"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/aud024-gap1-target}"
(cd "$here/probe" && cargo build --offline --release --quiet --bin decoy-collision) || exit 2
"$CARGO_TARGET_DIR/release/decoy-collision"
