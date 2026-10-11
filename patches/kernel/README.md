# Kernel patches

Patches that `scripts/build-qemu-kernel.sh` applies, in name order, to
bpf-next at `kernel-commit` before building the guest kernel and the
selftests. `make check-kernel-commit` checks that the kernel worktree is
the pin plus exactly these.

There are none. Every result in this repository is from unmodified
bpf-next.

Until 2026-10 the QEMU flavor was built with seven selftests and libbpf
patches inherited from the UML flavor's stack
([uml-veristat](https://github.com/mykola-lysenko/uml-veristat),
`patches/bpf-selftests-uml/` 0004, 0005, 0005b, 0007, 0007b, 0009, 0011).
They work around properties of a UML kernel and of veristat, and the
2026-10-10 nightly ran all 596 translations without them: the selftests
build has no errors and no runtime row differs because of them.
