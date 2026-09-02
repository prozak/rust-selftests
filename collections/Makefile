# Real Rust `alloc` collections in BPF, backed by a BPF arena through the
# libarena-rs crate (vendor/libarena-rs, git submodule — the code that used
# to live here). This directory is only the harness shim: it hands the
# crate's own Makefile this tree's LLVM, vmlinux.h, libbpf and qemu kernel.
#
#   make        build the crate's examples (cargo bpf --examples) + runner
#   make test   run every object under the qemu kernel via vng

HEIM     := $(abspath ../..)
BTOOLDIR ?= $(HEIM)/uml-harness/.build/bpftool-output-qemu
KERNEL   ?= $(HEIM)/uml-harness/.build/bpf-next-x86
VNG      ?= $(HOME)/.local/share/vng-venv/bin/vng

CRATE_VARS := LLVM_PREFIX=$(HEIM)/uml-harness/.build/llvm-install \
              LIBARENA_VMLINUX_H=$(BTOOLDIR)/vmlinux.h \
              LIBBPF_INCLUDE=$(BTOOLDIR)/libbpf/include \
              LIBBPF_LIBS="$(BTOOLDIR)/libbpf/libbpf.a -lelf -lz" \
              KERNEL_BZIMAGE=$(KERNEL)/arch/x86/boot/bzImage VNG=$(VNG)

all:
	$(MAKE) -C vendor/libarena-rs $(CRATE_VARS) all

test:
	PATH="$(dir $(VNG)):$$PATH" $(MAKE) -C vendor/libarena-rs $(CRATE_VARS) test-vng

clean:
	$(MAKE) -C vendor/libarena-rs clean

.PHONY: all test clean
