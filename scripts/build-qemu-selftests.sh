#!/bin/bash
# build-qemu-selftests.sh — build the BPF selftests for the QEMU/x86_64
# flavor: fresh output dir against the bpf-next-x86 worktree kernel,
# standard flags (no UML pt_regs define, kmods enabled). Mirrors the
# bpf-uml-selftests build.sh invocation minus the UML tweaks.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$(cd "${REPO}/.." && pwd)/uml-harness/.build"
KSRC="${BUILD}/bpf-next-x86"
OUT="${BUILD}/selftests-output-qemu"
LLVM_PREFIX="${LLVM_PREFIX:-${BUILD}/llvm-install}"

[ -f "${KSRC}/vmlinux" ] || { echo "x86_64 kernel not built yet (${KSRC}/vmlinux)" >&2; exit 1; }

mkdir -p "${OUT}"
# bpftool flavor dir expected by swap-and-test.sh's BPFTOOL derivation;
# the host bpftool from the UML flavor works for skeleton generation.
if [ ! -e "${BUILD}/bpftool-output-qemu" ]; then
    ln -s bpftool-output-heimdall "${BUILD}/bpftool-output-qemu"
fi

make -C "${KSRC}/tools/testing/selftests/bpf" \
    OUTPUT="${OUT}/" \
    CLANG="${LLVM_PREFIX}/bin/clang" \
    LLC="${LLVM_PREFIX}/bin/llc" \
    LD="${LLVM_PREFIX}/bin/ld.lld" \
    BPFTOOL="${BUILD}/bpftool-output-qemu/bpftool" \
    VMLINUX_BTF="${KSRC}/vmlinux" \
    ARCH=x86_64 SKIP_LLVM=1 BPF_STRICT_BUILD=0 \
    -j"$(nproc)" -k \
    test_progs

echo "=== selftests-output-qemu built ==="
ls "${OUT}/test_progs"
