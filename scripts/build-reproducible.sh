#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="$(
  python3 - <<'PY'
import tomllib
with open("Cargo.toml", "rb") as source:
    print("v" + tomllib.load(source)["package"]["version"])
PY
)"

# The output folder is a plain name inside the repository that .gitignore already covers, so
# a mistyped argument can never point the replacement below at another folder.
output_dir="${1:-canonical-output}"
if [[ ! "$output_dir" =~ ^canonical-output(-[A-Za-z0-9._]+)?$ ]]; then
  echo "The output folder must be canonical-output or canonical-output-<name>, not '$output_dir'." >&2
  exit 2
fi

# REPRODUCIBLE_NO_CACHE=1 rebuilds every stage from scratch. Comparing such a build with a cached
# one shows that the output does not depend on what the build cache happens to hold.
cache_flags=()
if [[ "${REPRODUCIBLE_NO_CACHE:-0}" == 1 ]]; then
  cache_flags=(--no-cache)
fi

# Build into a fresh folder and replace the previous output only after a complete build, so a
# failed or interrupted build keeps the last good assets.
staging="$(mktemp -d "$repo_root/canonical-output-staging.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
docker buildx build "${cache_flags[@]}" \
  --platform linux/amd64 \
  --target artifacts \
  --build-arg "RELEASE_VERSION=$version" \
  --output "type=local,dest=$staging" \
  -f Dockerfile.reproducible \
  .
if [[ ! -s "$staging/release/SHA256SUMS" ]]; then
  echo "The build finished without release/SHA256SUMS; the previous output is kept." >&2
  exit 1
fi
rm -rf "$output_dir"
mv "$staging" "$output_dir"
trap - EXIT
echo "Canonical release assets: $repo_root/$output_dir/release"
