#!/usr/bin/env bash
# AUD-024 verifier harness (review only): copies web/ to a scratch folder, removes five type
# assertions (web/client.js:769 and :1086, web/runtime.js:100 and :1150, web/wallet.js:304) and runs
# the page-side type check on the copy, to show which of them keep tsc quiet. Never touches web/.
# Exit 0 when tsc passes on the copy (no assertion was needed), 1 when it reports errors.
set -euo pipefail
scratch="${AUD024_SCRATCH:-../tmp/aud024/verifier-type-assertions}/web-uncast"
rm -rf "$scratch"
mkdir -p "$(dirname "$scratch")"
cp -r web "$scratch"
python3 - "$scratch" <<'PY'
import sys
root = sys.argv[1]
def sub(path, old, new):
    full = f"{root}/{path}"
    text = open(full).read()
    assert text.count(old) == 1, (path, old)
    open(full, "w").write(text.replace(old, new))
sub("client.js", "answerOwner(/** @type {PageOwner} */ (owner), check)", "answerOwner(owner, check)")
sub("client.js", "const { parameters, ...report } = /** @type {SetReport & { parameters: MhfeParameters }} */ (",
    "const { parameters, ...report } = (")
sub("runtime.js", "const ran = /** @type {SetReport} */ (", "const ran = (")
sub("runtime.js", "WebAssembly.compile(/** @type {BufferSource} */ (this.#wasm))", "WebAssembly.compile(this.#wasm)")
sub("wallet.js", "{ .../** @type {object} */ (result), workers: count }", "{ ...result, workers: count }")
print("removed 5 assertions in the copy")
PY
node_modules/.bin/tsc --version
set +e
node_modules/.bin/tsc -p "$scratch/tsconfig.json" | sed -E 's#^.*/web-uncast/#web-uncast/#'
code=${PIPESTATUS[0]}
echo "tsc exit $code"
exit "$code"
