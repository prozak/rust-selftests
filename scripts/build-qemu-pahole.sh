#!/bin/bash
# Build upstream pahole with wide-argument ABI support in an isolated prefix.
set -euo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
revision="$(cat "${repo}/pahole-commit")"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo "invalid pahole pin" >&2; exit 1; }
root="${repo}/bld/pahole-${revision}"
src="${root}/source"
install="${root}/install"

if [ ! -d "${src}/.git" ]; then
    mkdir -p "$root"
    git clone https://github.com/acmel/dwarves.git "$src"
fi
if [ -n "$(git -C "$src" status --porcelain --untracked-files=no)" ]; then
    echo "pahole source has local edits: $src" >&2
    exit 1
fi
if ! git -C "$src" cat-file -e "${revision}^{commit}"; then
    git -C "$src" fetch origin "$revision"
fi
git -C "$src" checkout --detach "$revision"
git -C "$src" submodule update --init --recursive
[ -z "$(git -C "$src" status --porcelain --untracked-files=no)" ]
# Include this recipe as well as the pinned source/submodule tree.
identity="$( { printf '%s\n' "$revision"; sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1; } | sha256sum | cut -d' ' -f1)"
if [ -x "${install}/bin/pahole" ] && [ -f "${install}/.build-id" ] && \
   [ "$(cat "${install}/.build-id")" = "$identity" ]; then
    echo "pahole $revision: reusing $install"
    exit 0
fi
mkdir -p "$install"
rm -f "${install}/.build-id"
cmake -S "$src" -B "${root}/build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$install" -DCMAKE_INSTALL_RPATH="${install}/lib" \
    -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DLIB_INSTALL_DIR=lib -DLIBBPF_EMBEDDED=ON
cmake --build "${root}/build" -j "${PAHOLE_BUILD_JOBS:-4}"
cmake --install "${root}/build"
"${install}/bin/pahole" --version
printf '%s\n' "$identity" > "${install}/.build-id"
