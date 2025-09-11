#!/usr/bin/env bash
set -euo pipefail

# Build schedscore binaries for specified Ubuntu releases in Docker
# Usage: scripts/build-static-in-docker.sh [ubuntu:22.04] [ubuntu:24.04]
# Defaults: ubuntu:22.04 ubuntu:24.04

here_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$here_dir/.." && pwd)

DISTROS=("ubuntu:22.04" "ubuntu:24.04")
if [[ $# -gt 0 ]]; then
  DISTROS=("$@")
fi

# Ensure dist directory exists
mkdir -p "$repo_root/dist"

run_build() {
  local image_tag="$1"
  local label
  case "$image_tag" in
    ubuntu:22.04) label="ubuntu-22.04";;
    ubuntu:24.04) label="ubuntu-24.04";;
    *) label="$(echo "$image_tag" | tr ':/' '--')";;
  esac

  echo "[INFO] Building binary inside $image_tag -> dist/$label/"
  docker pull "$image_tag" >/dev/null

  # Mount repo and run a dedicated build script inside the container
  docker run --rm \
    -v "$repo_root":/src \
    -w /src \
    --env STRICT=1 \
    --env LABEL="$label" \
    "$image_tag" bash -eu -o pipefail scripts/docker/build_ubuntu.sh
}

for d in "${DISTROS[@]}"; do
  run_build "$d"
done

echo "[INFO] Build artifacts:"
find "$repo_root/dist" -maxdepth 2 -type f -printf "%P\n" | sed 's/^/  - /'

