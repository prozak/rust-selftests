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

# Use the pinned upstream pahole: 1.31 drops the int128 tracing target's
# BTF because its parameter analysis does not account for register pairs.
bash "${REPO}/scripts/build-qemu-pahole.sh"
PAHOLE="${REPO}/bld/pahole-$(cat "${REPO}/pahole-commit")/install/bin/pahole"
export PAHOLE
export PATH="$(dirname "${PAHOLE}"):${PATH}"

mkdir -p "${OUT}"
# bpftool flavor dir expected by swap-and-test.sh's BPFTOOL derivation.
# It must come from THIS tree: skeleton generation opens every object with
# bpftool's libbpf, and an older libbpf rejects objects using newer ELF
# conventions (the 520d7d7-era UML bpftool fails on 3ccdb078's .percpu
# sections and ksym externs, and then test_progs never links).
BPFTOOL_OUT="${BUILD}/bpftool-output-qemu"
if [ ! -x "${BPFTOOL_OUT}/bpftool" ] || [ -n "${REBUILD_BPFTOOL:-}" ]; then
    rm -rf "${BPFTOOL_OUT}"
    mkdir -p "${BPFTOOL_OUT}"
    make -C "${KSRC}/tools/bpf/bpftool" OUTPUT="${BPFTOOL_OUT}/" \
        CLANG="${LLVM_PREFIX}/bin/clang" \
        LLVM_CONFIG="${LLVM_PREFIX}/bin/llvm-config" \
        LLVM_STRIP="${LLVM_PREFIX}/bin/llvm-strip" \
        -j"$(nproc)" all
fi

# libarena builds in the SOURCE tree and its Makefile does not track
# header dependencies, so after a checkout its objects keep calling
# functions the headers no longer export (bmp_test_bit after the inlining
# commit) and the libarena skeleton, then test_progs, fail to build.
git -C "${KSRC}" clean -fdXq -- tools/testing/selftests/bpf/libarena

# Module.symvers (via modules) so test_kmods builds against THIS kernel,
# not the host's /lib/modules fallback.
make -C "${KSRC}" -j"$(nproc)" modules

# Mirror bpf-uml-selftests build.sh: default goal, -k + BPF_STRICT_BUILD=0
# tolerate upstream-drifting selftests and link a PARTIAL test_progs — an
# explicit test_progs goal would make any failed skeleton fatal.
make -C "${KSRC}/tools/testing/selftests/bpf" \
    OUTPUT="${OUT}/" \
    CLANG="${LLVM_PREFIX}/bin/clang" \
    LLC="${LLVM_PREFIX}/bin/llc" \
    LD="${LLVM_PREFIX}/bin/ld.lld" \
    BPFTOOL="${BPFTOOL_OUT}/bpftool" \
    VMLINUX_BTF="${KSRC}/vmlinux" \
    ARCH=x86_64 SKIP_LLVM=1 BPF_STRICT_BUILD=0 \
    -j"$(nproc)" -k || true

echo "=== selftests-output-qemu build finished (partial failures tolerated) ==="
# Kbuild does not track changes to the pahole executable. Regenerate the
# test module's BTF even when its compiler/linker inputs were already current.
python3 "${REPO}/scripts/refresh-qemu-testmod-btf.py" --install
ls "${OUT}/test_progs"
ls "${OUT}"/test_kmods/bpf_testmod.ko 2>/dev/null || ls "${OUT}"/bpf_testmod.ko 2>/dev/null || echo "WARNING: bpf_testmod.ko missing"
