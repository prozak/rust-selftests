# Default locations of the QEMU-flavor build tree, shared by the shell
# scripts (source this file; it sets but does not export). Every variable
# keeps a value already present in the environment, so one override, usually
# BUILD_DIR, moves the whole tree. equiv/paths.py and the Makefile apply the
# same defaults.
#
#   BUILD_DIR         root of everything built from public sources (.build/)
#   KERNEL_SRC        bpf-next worktree at kernel-commit, built for x86_64
#   SELFTESTS_OUTPUT  tools/testing/selftests/bpf build output
#   LLVM_PREFIX       LLVM >= 22 install (scripts/fetch-llvm.sh)
#   QEMU_KERNEL       bzImage booted by virtme-ng

RS_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${RS_REPO}/.build}"
KERNEL_SRC="${KERNEL_SRC:-${BUILD_DIR}/bpf-next}"
SELFTESTS_SRC="${SELFTESTS_SRC:-${KERNEL_SRC}/tools/testing/selftests/bpf}"
SELFTESTS_OUTPUT="${SELFTESTS_OUTPUT:-${BUILD_DIR}/selftests-output-qemu}"
LLVM_PREFIX="${LLVM_PREFIX:-${BUILD_DIR}/llvm}"
VMLINUX_BTF="${VMLINUX_BTF:-${KERNEL_SRC}/vmlinux}"
QEMU_KERNEL="${QEMU_KERNEL:-${KERNEL_SRC}/arch/x86/boot/bzImage}"
