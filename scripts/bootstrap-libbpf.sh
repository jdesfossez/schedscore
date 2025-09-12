#!/usr/bin/env bash
set -euo pipefail
# Build a static libbpf from source and print CFLAGS and LIBS lines suitable for config.mk
# Usage: scripts/bootstrap-libbpf.sh [--tag v1.3.0] [--dest .vendor]
# Prints two lines to stdout:
#   CFLAGS=...
#   LIBS=...

TAG=v1.3.0
DEST=.vendor
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2;;
    --dest) DEST="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$ROOT/$DEST"
LIBBPF_DIR="$ROOT/$DEST/libbpf-$TAG"
if [[ ! -d "$LIBBPF_DIR" ]]; then
  git clone --depth 1 --branch "$TAG" https://github.com/libbpf/libbpf "$LIBBPF_DIR" 1>&2
fi
make -C "$LIBBPF_DIR/src" BUILD_STATIC_ONLY=1 NO_PKG_CONFIG=1 -j 1>&2

# Normalize include paths
CFLAGS="-I$LIBBPF_DIR/src -I$LIBBPF_DIR/include/uapi -I$LIBBPF_DIR/include -I$LIBBPF_DIR/src/compat"
LIBS="$LIBBPF_DIR/src/libbpf.a -lelf -lz -lpthread"

echo "CFLAGS='$CFLAGS'"
echo "LIBS='$LIBS'"

