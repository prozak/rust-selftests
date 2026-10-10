#!/bin/bash
# build-qemu-kernel.sh — build the x86_64 guest kernel of the QEMU flavor
# from public sources into KERNEL_SRC (default .build/bpf-next):
#
#   1. a shallow checkout of bpf-next at kernel-commit (BPF_NEXT_URL,
#      default git.kernel.org);
#   2. patches/kernel/*.patch applied as commits, in order (none if the
#      directory is empty), so `make check-kernel-commit` can count them;
#   3. kernel/config-x86_64 + olddefconfig;
#   4. vmlinux, bzImage and modules, with the pahole pinned in
#      pahole-commit for the kernel AND its modules: module BTF is
#      deduplicated against vmlinux BTF, and two pahole versions encode
#      some types differently.
#
# Re-running reuses the checkout and rebuilds incrementally.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${REPO}/scripts/paths.sh"
PIN="$(cat "${REPO}/kernel-commit")"
URL="${BPF_NEXT_URL:-https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git}"
KSRC="${KERNEL_SRC}"

if [ ! -d "${KSRC}/.git" ]; then
    mkdir -p "${KSRC}"
    git -C "${KSRC}" init -q
    git -C "${KSRC}" remote add origin "${URL}"
    git -C "${KSRC}" fetch --depth=1 origin "${PIN}"
    git -C "${KSRC}" checkout -q --detach FETCH_HEAD
    shopt -s nullglob
    patches=("${REPO}"/patches/kernel/*.patch)
    if [ "${#patches[@]}" -gt 0 ]; then
        git -C "${KSRC}" -c user.name=rust-selftests \
            -c user.email=rust-selftests@localhost am -q "${patches[@]}"
    fi
fi
make -C "${REPO}" -s check-kernel-commit KERNEL_SRC="${KSRC}"

bash "${REPO}/scripts/build-qemu-pahole.sh"
PAHOLE="${BUILD_DIR}/pahole-$(cat "${REPO}/pahole-commit")/install/bin/pahole"

# CONFIG_PAHOLE_VERSION is computed at configure time, so olddefconfig
# needs the same PAHOLE as the build.
cp "${REPO}/kernel/config-x86_64" "${KSRC}/.config"
make -C "${KSRC}" PAHOLE="${PAHOLE}" olddefconfig
make -C "${KSRC}" PAHOLE="${PAHOLE}" -j"$(nproc)" vmlinux bzImage modules
ls -l "${KSRC}/vmlinux" "${QEMU_KERNEL}"
