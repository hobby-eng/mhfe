#!/usr/bin/env bash
# Audit AUD-024, wallet-derivation role: runs the independent wallet oracle and the probes of
# mhfe's public API and of the built browser package's wallet bindings. See README.md.
#
#   docs/audits/AUD-024-harnesses/wallet-derivation/run.sh conformance|findings [work dir]
#
# conformance: exits 0 when every case passes (expected at b6fca69), 1 otherwise.
# findings: states the behaviour the cited rules require for AUD-024's wallet-derivation findings;
#           exits 1 while a defect is present (expected at b6fca69) and 0 once all are fixed.
# Run from the repository root. Needs python3, node, cargo (Rust 1.99.0), curl for the first run,
# prlimit (util-linux) for the thread case, and for the browser cases a built dist/ and
# target/wasm-bindgen/ (scripts/build-wasm.sh).
set -euo pipefail

mode="${1:-conformance}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(pwd)"
work="${2:-${TMPDIR:-/tmp}/aud024-wallet-derivation}"
mkdir -p "$work/refs" "$work/probe/src/bin"
export REFS_DIR="$work/refs" OUT_DIR="$work" MHFE_ROOT="$root"

# Public reference documents, read-only, checked against the hashes this audit recorded.
fetch() {
  local name="$1" url="$2"
  [ -s "$REFS_DIR/$name" ] || curl -sSf -m 60 -o "$REFS_DIR/$name" "$url"
}
bips=https://raw.githubusercontent.com/bitcoin/bips/master
for bip in bip-0032 bip-0049 bip-0084 bip-0086 bip-0173 bip-0350; do
  fetch "$bip.mediawiki" "$bips/$bip.mediawiki"
done
fetch bip39-english.txt "$bips/bip-0039/english.txt"
fetch bip39-vectors.json https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json
fetch slip-0014.md https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0014.md
fetch slip-0014-addresses.md https://raw.githubusercontent.com/satoshilabs/slips/master/slip-0014/addresses.md
fetch dip-0017.md https://raw.githubusercontent.com/dashpay/dips/master/dip-0017.md
fetch dip-0018.md https://raw.githubusercontent.com/dashpay/dips/master/dip-0018.md
fetch eip-55.md https://raw.githubusercontent.com/ethereum/ERCs/master/ERCS/erc-55.md
fetch cashaddr.md https://raw.githubusercontent.com/bitcoincashorg/bitcoincash.org/master/spec/cashaddr.md
(cd "$REFS_DIR" && sha256sum --quiet -c "$here/refs.sha256")

python3 "$here/validate_oracle.py"
python3 "$here/gen_cases.py"
python3 "$here/gen_wasm_cases.py"

# The probe crate, built against this checkout through its public API only.
cat > "$work/probe/Cargo.toml" <<EOF
[package]
name = "aud024-wallet-probe"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
mhfe-experimental = { path = "$root" }
serde_json = "=1.0.151"
hex = "=0.4.3"

[workspace]
EOF
cp "$here/probe/rust-toolchain.toml" "$work/probe/"
cp "$here/probe/src/main.rs" "$work/probe/src/main.rs"
cp "$here/probe/src/bin/messages.rs" "$here/probe/src/bin/threads.rs" "$work/probe/src/bin/"
[ -f "$work/probe/Cargo.lock" ] || cp "$root/Cargo.lock" "$work/probe/Cargo.lock"
target="${CARGO_TARGET_DIR:-$work/target}"
(cd "$work/probe" && CARGO_TARGET_DIR="$target" cargo build --offline --release --quiet)
bin="$target/release"

status=0
if [ "$mode" = conformance ]; then
  "$bin/aud024-wallet-probe" "$work/conformance.json" | tail -1 || status=1
  "$bin/threads" || status=1
  "$bin/threads" draw || status=1
  node "$here/wasm_probe.mjs" "$root" "$work/wasm-cases.json" | tail -1 || status=1
else
  "$bin/aud024-wallet-probe" "$work/findings.json" || status=1
  node "$here/wasm_probe.mjs" "$root" "$work/wasm-cases.json" findings || status=1
  node "$here/check_passphrase_probe.mjs" "$root" || status=1
  node "$here/wallet_check_reference_probe.mjs" "$root" || status=1
  node "$here/owner_answer_probe.mjs" "$root" || status=1
  # The decoy search when the system refuses new threads: it must not panic.
  prlimit --nproc=1 "$bin/threads" || { echo "FAIL the decoy search panics when a thread is refused"; status=1; }
  "$bin/messages"
  # check() resolves to { outcome, path, evidence }: no document may still name a "matches" field.
  if grep -n "{ matches, path\|matches is true" docs/API.md docs/BROWSER-PACKAGE.md; then
    echo "FAIL the documents name check()'s former matches field"
    status=1
  fi
fi
exit "$status"
