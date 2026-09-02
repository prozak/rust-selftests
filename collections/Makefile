# Real Rust `alloc` collections in BPF, backed by a BPF arena through the
# libarena-rs crate (vendor/libarena-rs, git submodule — the code that used
# to live here). This directory is only the harness shim: it points the
# crate's pipeline at this tree's LLVM, vmlinux.h, libbpf and qemu kernel,
# and builds/runs the crate's example programs.
#
#   make        build vendor/libarena-rs/examples/progs/*.rs -> bld/*.bpf.o
#   make test   run every object under the qemu kernel via vng

HEIM     := $(abspath ../..)
BTOOLDIR ?= $(HEIM)/uml-harness/.build/bpftool-output-qemu
KERNEL   ?= $(HEIM)/uml-harness/.build/bpf-next-x86
VNG      ?= $(HOME)/.local/share/vng-venv/bin/vng

LIBARENA_RS    := vendor/libarena-rs
LLVM_PREFIX    ?= $(HEIM)/uml-harness/.build/llvm-install
VMLINUX_H      := $(BTOOLDIR)/vmlinux.h
LIBBPF_INCLUDE := $(BTOOLDIR)/libbpf/include
LIBBPF_LIBS    := $(BTOOLDIR)/libbpf/libbpf.a -lelf -lz
BPF_PROGS_DIR  := $(LIBARENA_RS)/examples/progs

include $(LIBARENA_RS)/mk/libarena.mk

RUNNER := $(LIBARENA_RS_BLD)/arena-runner

all: $(LIBARENA_RS_PROG_OBJS) $(RUNNER)

test: all
	PATH="$(dir $(VNG)):$$PATH" $(VNG) --run $(KERNEL)/arch/x86/boot/bzImage \
		--cpus 2 --memory 2G --rw -- \
		'cd $(CURDIR) && for o in $(LIBARENA_RS_PROG_OBJS); do $(RUNNER) $$o || exit 1; done'

clean: libarena-rs-distclean

.PHONY: all test clean
