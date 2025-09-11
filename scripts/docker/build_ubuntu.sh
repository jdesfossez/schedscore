#!/usr/bin/env bash
set -euo pipefail

# This script is executed inside the Ubuntu Docker container by
# scripts/build-static-in-docker.sh. It:
# - Installs build deps and the default Ubuntu kernel image to obtain vmlinux
# - Prefers distro bpftool (linux-tools-<kver>), with upstream fallback
# - Generates vmlinux.h from the installed kernel's vmlinux
# - Builds schedscore and writes artifact to dist/$LABEL/

LABEL=${LABEL:-"ubuntu-unknown"}
STRICT=${STRICT:-1}
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y --no-install-recommends \
  build-essential clang llvm pkg-config libelf-dev zlib1g-dev libbpf-dev \
  ca-certificates git curl make cmake \
  linux-tools-common linux-tools-generic ubuntu-dbgsym-keyring

# Enable ddebs to fetch -dbgsym packages
. /etc/os-release || true
if [[ -n "${UBUNTU_CODENAME:-}" ]]; then
  echo "deb http://ddebs.ubuntu.com $UBUNTU_CODENAME main restricted universe multiverse" > /etc/apt/sources.list.d/ddebs.list
  echo "deb http://ddebs.ubuntu.com $UBUNTU_CODENAME-updates main restricted universe multiverse" >> /etc/apt/sources.list.d/ddebs.list
  echo "deb http://ddebs.ubuntu.com $UBUNTU_CODENAME-proposed main restricted universe multiverse" >> /etc/apt/sources.list.d/ddebs.list
  apt-get update -y || true
fi

# Determine the default kernel version provided by linux-image-generic
DEFAULT_KERNEL=$(apt-cache depends linux-image-generic 2>/dev/null | awk '/Depends: linux-image-/ {print $2}' | sed 's/linux-image-//' | head -n1 || true)
if [[ -z "$DEFAULT_KERNEL" ]]; then
  echo "[ERROR] Could not determine default kernel version from linux-image-generic" >&2
  exit 1
fi
echo "[INFO] Default kernel (from linux-image-generic): $DEFAULT_KERNEL"

# Install matching linux-tools (for distro bpftool if available)
apt-get install -y --no-install-recommends linux-tools-$DEFAULT_KERNEL || true

# Install debug symbols package to get /usr/lib/debug/boot/vmlinux-<kver>
apt-get install -y --no-install-recommends linux-image-$DEFAULT_KERNEL-dbgsym || \
  apt-get install -y --no-install-recommends linux-image-unsigned-$DEFAULT_KERNEL-dbgsym

VMLINUX="/usr/lib/debug/boot/vmlinux-$DEFAULT_KERNEL"
if [[ ! -s "$VMLINUX" ]]; then
  echo "[ERROR] vmlinux not found at $VMLINUX (install -dbgsym)." >&2
  exit 1
fi

# Build recent libbpf and link statically to avoid old system libbpf at runtime
LIBBPF_TAG=${LIBBPF_TAG:-v1.3.0}
LIBBPF_SRC=$(mktemp -d)
GIT_LFS="https://github.com/libbpf/libbpf"
echo "[INFO] Cloning libbpf $LIBBPF_TAG"
 git clone --depth 1 --branch "$LIBBPF_TAG" "$GIT_LFS" "$LIBBPF_SRC"
make -C "$LIBBPF_SRC/src" BUILD_STATIC_ONLY=1 NO_PKG_CONFIG=1 -j
# Prepare flags so Makefile uses our static libbpf
export LIBBPF_CFLAGS="-I$LIBBPF_SRC/src -I$LIBBPF_SRC/include/uapi -I$LIBBPF_SRC/include"
export LIBBPF_LIBS="$LIBBPF_SRC/src/libbpf.a -lelf -lz -lpthread"

# Locate bpftool: prefer versioned path matching DEFAULT_KERNEL; then others; then build
if [[ -x "/usr/lib/linux-tools-$DEFAULT_KERNEL/bpftool" ]]; then
  BPFTOOL_BIN="/usr/lib/linux-tools-$DEFAULT_KERNEL/bpftool"
else
  CANDIDATE=$(sh -c 'ls -1 /usr/lib/linux-tools-*/bpftool 2>/dev/null | head -n1 || true')
  if [[ -n "$CANDIDATE" ]]; then
    BPFTOOL_BIN="$CANDIDATE"
  elif command -v bpftool >/dev/null 2>&1; then
    # Fallback to whatever bpftool is on PATH (may be a wrapper tied to host kernel)
    BPFTOOL_BIN=$(command -v bpftool)
  else
    echo "[INFO] Distro bpftool not found; building upstream bpftool"
    tmpd=$(mktemp -d)
    git clone https://github.com/libbpf/bpftool "$tmpd/bpftool"
    cd "$tmpd/bpftool"
    git submodule update --init --recursive
    make -C src -j
    install -m 0755 src/bpftool /usr/local/bin/bpftool
    cd /src
    BPFTOOL_BIN=/usr/local/bin/bpftool
  fi
fi

echo "[INFO] Using bpftool at: $BPFTOOL_BIN"

# Generate vmlinux.h from the installed kernel's vmlinux (not from host /sys)
"$BPFTOOL_BIN" btf dump file "$VMLINUX" format c > vmlinux.h

# Build
make clean
STRICT=$STRICT make -j BPFTOOL_BIN="$BPFTOOL_BIN" VMLINUX_BTF="$VMLINUX"

# Collect artifact
mkdir -p "dist/$LABEL"
cp -v schedscore "dist/$LABEL/schedscore"

echo "[INFO] Build for $LABEL complete. Artifact: dist/$LABEL/schedscore"

