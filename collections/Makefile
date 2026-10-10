# Real Rust `alloc` collections in BPF, backed by a BPF arena through the
# libarena-rs crate (vendor/libarena-rs, git submodule — the code that used
# to live here). This directory is only the harness shim: it hands the
# crate's own Makefile this tree's LLVM, vmlinux.h, libbpf and qemu kernel.
#
#   make        build the crate's examples (cargo bpf --examples) + runner
#   make test   run every object under the qemu kernel via vng

# Same defaults as ../scripts/paths.sh.
BUILD_DIR   ?= $(abspath ..)/.build
BTOOLDIR    ?= $(BUILD_DIR)/bpftool-output-qemu
KERNEL      ?= $(BUILD_DIR)/bpf-next
LLVM_PREFIX ?= $(BUILD_DIR)/llvm
VNG         ?= $(or $(shell command -v vng),$(BUILD_DIR)/vng-venv/bin/vng)

CRATE_VARS := LLVM_PREFIX=$(LLVM_PREFIX) \
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
