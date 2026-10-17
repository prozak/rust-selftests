#!/bin/bash
# build-llvm.sh — build the LLVM this repo builds with from source into
# LLVM_PREFIX (default .build/llvm): llvm-project release/23.x at LLVM_COMMIT
# plus the patches in patches/llvm/, projects clang and lld, targets X86 and
# BPF, Release. About 40 minutes and 2 GB on a 32-way host.
#
# This replaces scripts/fetch-llvm.sh for as long as patches/llvm/ is not
# empty: the release tarballs lack those patches (today the unused
# llvm.bpf.preserve.field.info crash, issue #49), and every translation is
# built with the same LLVM_PREFIX. When upstream carries them, drop the
# patches and go back to fetch-llvm.sh.
#
#   LLVM_SRC    an llvm-project checkout to build as it stands (default: the
#               script's own clone in .build/llvm-project, checked out at
#               LLVM_COMMIT with the patches applied by git am)
#   LLVM_BUILD  the CMake build directory (default .build/llvm-build)
#   JOBS        ninja parallelism (default nproc); LINK_JOBS caps the
#               parallel links (default 4: a clang link takes ~3 GB)

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${REPO}/scripts/paths.sh"

LLVM_COMMIT=0cd28174a1f64e5a8df194422ebf46e88cff33ad   # release/23.x, 2026-10-14
LLVM_URL=https://github.com/llvm/llvm-project.git
LLVM_BUILD="${LLVM_BUILD:-${BUILD_DIR}/llvm-build}"
JOBS="${JOBS:-$(nproc)}"
LINK_JOBS="${LINK_JOBS:-4}"

patches=("${REPO}"/patches/llvm/*.patch)
[ -e "${patches[0]}" ] || patches=()
stamp="$(printf '%s\n' "${LLVM_COMMIT}" "${patches[@]##*/}" | cat - "${patches[@]}" | sha256sum | cut -c1-16)"

if [ -x "${LLVM_PREFIX}/bin/llc" ] && \
   [ "$(cat "${LLVM_PREFIX}/.rust-selftests-source" 2>/dev/null)" = "${stamp}" ]; then
    echo "LLVM ${LLVM_COMMIT:0:12} + ${#patches[@]} patch(es): reusing ${LLVM_PREFIX}"
    exit 0
fi

if [ -z "${LLVM_SRC:-}" ]; then
    LLVM_SRC="${BUILD_DIR}/llvm-project"
    if [ ! -d "${LLVM_SRC}/.git" ]; then
        mkdir -p "${BUILD_DIR}"
        git clone --no-checkout --filter=blob:none "${LLVM_URL}" "${LLVM_SRC}"
    fi
    git -C "${LLVM_SRC}" cat-file -e "${LLVM_COMMIT}^{commit}" 2>/dev/null || \
        git -C "${LLVM_SRC}" fetch origin "${LLVM_COMMIT}"
    git -C "${LLVM_SRC}" checkout -q --detach "${LLVM_COMMIT}"
    for p in "${patches[@]}"; do
        git -C "${LLVM_SRC}" am -q "${p}"
    done
fi
# Whatever the checkout, every patch must be in it: reverse-apply checks.
for p in "${patches[@]}"; do
    git -C "${LLVM_SRC}" apply --check -R "${p}" || {
        echo "build-llvm.sh: ${p##*/} is not applied in ${LLVM_SRC}" >&2; exit 1; }
done
echo "source: ${LLVM_SRC} at $(git -C "${LLVM_SRC}" rev-parse --short HEAD), ${#patches[@]} patch(es)"

cmake_args=(
    -G Ninja
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_INSTALL_PREFIX="${LLVM_PREFIX}"
    -DLLVM_ENABLE_PROJECTS="clang;lld"
    -DLLVM_TARGETS_TO_BUILD="X86;BPF"
    -DLLVM_ENABLE_ASSERTIONS=OFF
    -DLLVM_INCLUDE_TESTS=OFF
    -DLLVM_INCLUDE_EXAMPLES=OFF
    -DLLVM_INCLUDE_BENCHMARKS=OFF
    -DLLVM_INCLUDE_DOCS=OFF
    -DLLVM_PARALLEL_LINK_JOBS="${LINK_JOBS}"
)
if command -v clang >/dev/null && command -v clang++ >/dev/null; then
    cmake_args+=(-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++)
fi
if command -v ld.lld >/dev/null; then
    cmake_args+=(-DLLVM_ENABLE_LLD=ON)
fi
cmake -S "${LLVM_SRC}/llvm" -B "${LLVM_BUILD}" "${cmake_args[@]}"
ninja -C "${LLVM_BUILD}" -j "${JOBS}"

stage="${LLVM_PREFIX}.stage"
rm -rf "${stage}"
DESTDIR="${stage}" ninja -C "${LLVM_BUILD}" install >/dev/null
echo "${stamp}" > "${stage}${LLVM_PREFIX}/.rust-selftests-source"
rm -rf "${LLVM_PREFIX}"
mkdir -p "$(dirname "${LLVM_PREFIX}")"
mv "${stage}${LLVM_PREFIX}" "${LLVM_PREFIX}"
rm -rf "${stage}"
"${LLVM_PREFIX}/bin/llvm-config" --version
