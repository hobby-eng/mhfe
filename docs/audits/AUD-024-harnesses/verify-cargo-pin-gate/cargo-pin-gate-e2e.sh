#!/usr/bin/env bash
# AUD-024 harness (commit b6fca69): runs the repository's scripts/verify-code-rules.mjs, unchanged,
# end to end in a throwaway git repository whose Cargo.toml is one crafted manifest at a time, and
# exits 1 when a manifest with a dependency that is not pinned as "=x.y.z" passes the gate.
#
#   docs/audits/AUD-024-harnesses/verify-cargo-pin-gate/cargo-pin-gate-e2e.sh   (from the root)
set -euo pipefail
src="$(pwd)"
[ -f "$src/scripts/verify-code-rules.mjs" ] || { echo "run from the repository root" >&2; exit 2; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
missed=0
run() {
  local what="$1" manifest="$2" refuse="$3"
  rm -rf "$work/repo"; mkdir -p "$work/repo/scripts"
  cp "$src/scripts/verify-code-rules.mjs" "$src/scripts/gate-command-line.mjs" "$work/repo/scripts/"
  printf '{"packageManager":"pnpm@10.0.0","devDependencies":{"a":"1.2.3"}}\n' > "$work/repo/package.json"
  : > "$work/repo/pnpm-lock.yaml"
  printf '%b' "$manifest" > "$work/repo/Cargo.toml"
  git -C "$work/repo" init -q
  local out code
  set +e
  out="$(cd "$work/repo" && node scripts/verify-code-rules.mjs 2>&1)"; code=$?
  set -e
  echo "gate exit $code  $what"
  echo "$out" | sed 's/^/      /'
  if [ "$refuse" = yes ] && [ "$code" -eq 0 ]; then missed=$((missed + 1)); fi
  if [ "$refuse" = no ] && [ "$code" -ne 0 ]; then missed=$((missed + 1)); fi
}
run 'control, refused: foo = "1.2" in [dependencies]' '[dependencies]\nfoo = "1.2"\n' yes
run 'control, passes: foo = "=1.2.3" in [dependencies]' '[dependencies]\nfoo = "=1.2.3"\n' no
run '[dependencies.foo] table, version = "1.2"' '[dependencies.foo]\nversion = "1.2"\n' yes
run '[dependencies.foo] table, git source and no version' '[dependencies.foo]\ngit = "https://example.invalid/foo"\n' yes
run "[target.'cfg(unix)'.dependencies.foo] table, version = \"*\"" "[target.'cfg(unix)'.dependencies.foo]\nversion = \"*\"\n" yes
run '[dev-dependencies.foo] table, version = "^1"' '[dev-dependencies.foo]\nversion = "^1"\n' yes
run '[build-dependencies.cc] table, version = ">=1"' '[build-dependencies.cc]\nversion = ">=1"\n' yes
run 'indented key: "  foo = \"1.2\""' '[dependencies]\n  foo = "1.2"\n' yes
run 'quoted key: "\"foo\" = \"1.2\""' '[dependencies]\n"foo" = "1.2"\n' yes
run 'dotted key: "foo.version = \"1.2\""' '[dependencies]\nfoo.version = "1.2"\n' yes
run 'section header with a comment: "[dependencies] # runtime"' '[package]\nname = "p"\n[dependencies] # runtime\nfoo = "1.2"\n' yes
if [ "$missed" -gt 0 ]; then
  echo "FAIL: $missed manifests decided wrong; Cargo reads each as a dependency (see README.md)"
  exit 1
fi
echo "PASS: the gate refuses every manifest with a dependency not pinned as \"=x.y.z\""
