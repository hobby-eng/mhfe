#!/usr/bin/env bash
# AUD-024 gap-1-browser-argon2-heap-residue: prints, with line numbers, the source and document lines
# the findings and checks of this role cite, at the commit checked out (b6fca69). Read-only.
#   source-lines.sh <repository root> <pretty-printed threaded glue>
set -euo pipefail
root="$1"
glue="$2"
show() {
  echo "== $1:$2-$3"
  awk -v a="$2" -v b="$3" 'NR>=a && NR<=b {printf "%5d  %s\n", NR, $0}' "$root/$1"
}
cd "$root"
echo "HEAD $(git rev-parse HEAD); tracked changes: $(git status --porcelain --untracked-files=no | wc -l)"
sha256sum dist/core/argon2-mt.js dist/core/argon2-st.js web/argon2-engine.js scripts/build-argon2-wasm.sh
show vendor/phc-winner-argon2/src/ref.c 39 47
show vendor/phc-winner-argon2/src/ref.c 79 81
show vendor/phc-winner-argon2/src/ref.c 90 98
show vendor/phc-winner-argon2/src/opt.c 110 113
show vendor/phc-winner-argon2/src/opt.c 184 187
show vendor/phc-winner-argon2/src/opt.c 270 283
show vendor/phc-winner-argon2/src/core.c 115 124
show vendor/phc-winner-argon2/src/core.c 134 153
show vendor/phc-winner-argon2/src/core.c 155 187
show vendor/phc-winner-argon2/src/core.c 280 290
show vendor/phc-winner-argon2/src/core.c 311 372
show vendor/phc-winner-argon2/src/argon2.c 82 97
show vendor/phc-winner-argon2/src/argon2.c 127 176
show vendor/phc-winner-argon2/src/thread.c 25 55
show vendor/phc-winner-argon2/include/argon2.h 85 95
show web/argon2-engine.js 1 88
show scripts/build-argon2-wasm.sh 36 79
show src/engine/browser.rs 9 11
show src/engine/browser.rs 73 103
show src/engine/ffi.rs 172 193
show src/engine/ffi.rs 380 383
show src/engine/native.rs 99 108
show src/wasm_api/core.rs 676 684
show src/wasm_api/core/hidden.rs 47 72
show scripts/package-check/argon2-faults.mjs 132 151
show SECURITY.md 39 53
show SECURITY.md 66 79
show SECURITY.md 170 178
show SECURITY.md 243 268
show docs/BROWSER-PACKAGE.md 730 736
show docs/BROWSER-PACKAGE.md 1017 1040
show docs/API.md 450 455
echo "== threaded glue (dist/core/argon2-mt.js, pretty-printed, base64 binary elided): $glue"
grep -n -A3 "initMainThread() {" "$glue"
grep -n -A7 "returnWorkerToPool: (worker)" "$glue"
grep -n -A6 "function establishStackSpace" "$glue"
grep -n -A3 "function __emscripten_thread_cleanup" "$glue"
grep -n -A8 "var growMemory" "$glue"
echo "== dynamic code in the two builds (eval, new Function, Function constructor):"
for file in dist/core/argon2-mt.js dist/core/argon2-st.js; do
  printf '%s: %s\n' "$file" "$(grep -c -E '\beval\s*\(|new Function|\bFunction\s*\(' "$file" || true)"
done
echo "== non-ASCII bytes in the two builds:"
for file in dist/core/argon2-mt.js dist/core/argon2-st.js; do
  printf '%s: %s\n' "$file" "$(LC_ALL=C grep -c -P '[^\x00-\x7F]' "$file" || true)"
done
