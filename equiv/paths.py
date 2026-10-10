"""Default locations of the QEMU-flavor build tree (see scripts/paths.sh).

Every value honours the environment variable of the same name, so the
Makefile's exports and a single BUILD_DIR override both reach the Python
tooling.
"""
import os

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_DIR = os.environ.get("BUILD_DIR") or os.path.join(REPO, ".build")
KERNEL_SRC = os.environ.get("KERNEL_SRC") or os.path.join(BUILD_DIR, "bpf-next")
SELFTESTS_SRC = os.environ.get("SELFTESTS_SRC") or os.path.join(
    KERNEL_SRC, "tools", "testing", "selftests", "bpf")
SELFTESTS_OUTPUT = os.environ.get("SELFTESTS_OUTPUT") or os.path.join(
    BUILD_DIR, "selftests-output-qemu")
LLVM_PREFIX = os.environ.get("LLVM_PREFIX") or os.path.join(BUILD_DIR, "llvm")
VMLINUX_BTF = os.environ.get("VMLINUX_BTF") or os.path.join(KERNEL_SRC, "vmlinux")
QEMU_KERNEL = os.environ.get("QEMU_KERNEL") or os.path.join(
    KERNEL_SRC, "arch", "x86", "boot", "bzImage")
