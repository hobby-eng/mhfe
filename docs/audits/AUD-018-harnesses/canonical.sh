#!/usr/bin/env bash
# Keep the documented build wrapper; add only task-scoped BuildKit memory parenting.
set -euo pipefail
unit="${MHFE_AUDIT_UNIT:?Transient unit identity required}"
MHFE_BUILD_CGROUP="$(systemctl --user show "$unit" --property=ControlGroup --value)"
export MHFE_BUILD_CGROUP
docker() {
  if [[ "${1:-}" == buildx && "${2:-}" == build ]]; then
    shift 2
    command docker buildx build --cgroup-parent "$MHFE_BUILD_CGROUP" "$@"
  else
    command docker "$@"
  fi
}
export -f docker
scripts/build-reproducible.sh "${1:-canonical-output-aud018}"
