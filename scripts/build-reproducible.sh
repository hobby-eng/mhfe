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
output_dir="${1:-canonical-output}"
rm -rf "$output_dir"
docker buildx build \
  --platform linux/amd64 \
  --target artifacts \
  --build-arg "RELEASE_VERSION=$version" \
  --output "type=local,dest=$output_dir" \
  -f Dockerfile.reproducible \
  .
echo "Canonical release assets: $repo_root/$output_dir/release"
