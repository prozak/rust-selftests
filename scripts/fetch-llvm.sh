#!/bin/bash
# fetch-llvm.sh — install the LLVM release this repo builds with into
# LLVM_PREFIX (default .build/llvm): the official llvm-project binary
# tarball, checked against its published sha256. LLVM_TARBALL=<file> uses
# an already downloaded copy instead of fetching it.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${REPO}/scripts/paths.sh"

VERSION=22.1.8
NAME="LLVM-${VERSION}-Linux-X64.tar.xz"
SHA256=df0e1ecf16caf3489a272a5eea4eec9b0d82878f6477fa309504f918a0006384
URL="https://github.com/llvm/llvm-project/releases/download/llvmorg-${VERSION}/${NAME}"

if [ -x "${LLVM_PREFIX}/bin/llc" ] && \
   "${LLVM_PREFIX}/bin/llvm-config" --version | grep -qx "${VERSION}"; then
    echo "LLVM ${VERSION}: reusing ${LLVM_PREFIX}"
    exit 0
fi

tarball="${LLVM_TARBALL:-${BUILD_DIR}/${NAME}}"
if [ ! -f "${tarball}" ]; then
    mkdir -p "$(dirname "${tarball}")"
    curl -fL --retry 3 -o "${tarball}.part" "${URL}"
    mv "${tarball}.part" "${tarball}"
fi
echo "${SHA256}  ${tarball}" | sha256sum -c -

rm -rf "${LLVM_PREFIX}.part"
mkdir -p "${LLVM_PREFIX}.part"
tar -xJf "${tarball}" -C "${LLVM_PREFIX}.part" --strip-components=1
rm -rf "${LLVM_PREFIX}"
mv "${LLVM_PREFIX}.part" "${LLVM_PREFIX}"
"${LLVM_PREFIX}/bin/llvm-config" --version
