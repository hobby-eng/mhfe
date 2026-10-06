#!/usr/bin/env bash
# Runs the canonical build's two cross-target clippy checks on a source tree read from stdin (tar).
set -euo pipefail
docker run --rm -i --network=none -e CARGO_NET_OFFLINE=true mhfe-deps:local bash -c '
  mkdir /w && cd /w && tar -xf -
  status=0
  for target in aarch64-unknown-linux-gnu x86_64-pc-windows-gnu; do
    echo "== clippy --target $target"
    cargo clippy --locked --offline --all-targets --all-features --target "$target" -- -D warnings || status=$?
  done
  exit $status'
