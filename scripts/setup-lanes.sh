#!/bin/bash
# setup-lanes.sh [N] — prepare N parallel sweep lanes (default 4).
#
# Each lane is a git worktree of this repo (own bld/, own bpf-rs-core
# copy for agent helper additions) plus a private copy of the QEMU
# selftests output (the mutable state: swapped objects, skeletons,
# test_progs relinks). Kernel worktree and vmlinux BTF are shared
# read-only. Re-running is idempotent.

set -euo pipefail
N="${1:-4}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT="$(dirname "${REPO}")"
BUILD="${PARENT}/uml-harness/.build"
SRC_OUT="${BUILD}/selftests-output-qemu"

[ -x "${SRC_OUT}/test_progs" ] || { echo "qemu selftests output missing" >&2; exit 1; }

for i in $(seq 1 "${N}"); do
    WT="${PARENT}/rust-selftests-lane${i}"
    if [ ! -d "${WT}" ]; then
        git -C "${REPO}" worktree add "${WT}" HEAD
        echo "[lane${i}] worktree: ${WT}"
    fi
    OUT="${BUILD}/selftests-output-qemu-lane${i}"
    if [ ! -d "${OUT}" ]; then
        cp -a "${SRC_OUT}" "${OUT}"
        # drop stale .corig backups so each lane re-snapshots pristine
        # objects on first swap
        rm -f "${OUT}"/*.bpf.o.corig
        echo "[lane${i}] output: ${OUT}"
    fi
    # bpftool flavor dir expected by swap-and-test's derivation
    ln -sfn bpftool-output-heimdall "${BUILD}/bpftool-output-qemu-lane${i}"
done
echo "lanes ready: ${N}"
