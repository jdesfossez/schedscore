#!/usr/bin/env bash
set -euo pipefail
# Build bpftool from source (if needed) and print path suitable for config.mk
# Usage: scripts/bootstrap-bpftool.sh [--dest .vendor]
# Prints one line to stdout:
#   BPFTOOL_BIN=/path/to/bpftool

DEST=.vendor
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest) DEST="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

if command -v bpftool >/dev/null 2>&1; then
  echo "BPFTOOL_BIN=$(command -v bpftool)"
  exit 0
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$ROOT/$DEST"
BPFDIR="$ROOT/$DEST/bpftool"
if [[ ! -d "$BPFDIR" ]]; then
  git clone --depth 1 https://github.com/libbpf/bpftool "$BPFDIR"
  (cd "$BPFDIR" && git submodule update --init --recursive)
fi
make -C "$BPFDIR/src" -j
install -m 0755 "$BPFDIR/src/bpftool" "$ROOT/$DEST/bpftool-bin"

echo "BPFTOOL_BIN=$ROOT/$DEST/bpftool-bin"

