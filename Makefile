# SPDX-License-Identifier: GPL-2.0
#
# Rust translations of the kernel BPF selftests BPF programs.
#
# This repo mirrors tools/testing/selftests/bpf in structure: for a C program
# progs/<name>.c in the kernel tree, the translation lives at progs/<name>.rs
# here. Everything else — prog_tests/*.c, test_progs, skeleton generation —
# is reused VERBATIM from the kernel selftests build this repo points at.
#
# Pipeline (4ast/rust-bpf, no aya, no bpf-linker):
#   rustc --emit=llvm-bc -> llvm-link (+libcore/liballoc) -> bpf-postproc
#   -> opt (internalize+O2) -> add_ksyms.py -> llc -mcpu=v4
#
# Main targets:
#   make [all]           build bld/<name>.bpf.o for every progs/*.rs
#   make verify          run all built objects through the kernel verifier (UML)
#   make test-<name>     swap Rust object into the selftests output, regenerate
#                        skeletons + test_progs via the kernel Makefile, run the
#                        affected test(s) in UML
#   make restore-<name>  put the original C object back and rebuild harness
#   make status          translation coverage vs the kernel progs/ directory
#
# Configuration (override via environment or command line):
#   KERNEL_SRC        bpf-next checkout (with built selftests)
#   SELFTESTS_OUTPUT  the selftests build output directory (contains *.bpf.o,
#                     test_progs, generated skeletons)
#   RUSTBPF           4ast/rust-bpf checkout with built bld_deps/ and tools
#   LLVM_PREFIX       LLVM >= 22 install (llc/opt/llvm-link/llvm-readelf...)
#   UML_HARNESS       bpf-uml-selftests checkout (uml-veristat/uml-test-progs)
#   UML_INSTALL_DIR   uml-veristat install to boot (kernel, modules)

# FLAVOR selects the oracle: uml (default) or qemu (x86_64 kernel worktree
# + vng runner; ~10x faster, has kprobes/uprobes/stack unwinding).
FLAVOR ?= uml
ifeq ($(FLAVOR),qemu)
KERNEL_SRC ?= $(abspath $(CURDIR)/../uml-harness/.build/bpf-next-x86)
SELFTESTS_OUTPUT ?= $(abspath $(CURDIR)/../uml-harness/.build/selftests-output-qemu)
VMLINUX_BTF ?= $(KERNEL_SRC)/vmlinux
TEST_RUNNER ?= $(CURDIR)/scripts/qemu-test-progs
export VMLINUX_BTF TEST_RUNNER
else
KERNEL_SRC ?= $(abspath $(CURDIR)/../uml-harness/.build/bpf-next)
SELFTESTS_OUTPUT ?= $(abspath $(CURDIR)/../uml-harness/.build/selftests-output-heimdall)
VMLINUX_BTF ?= $(KERNEL_SRC)/linux
endif
SELFTESTS_SRC := $(KERNEL_SRC)/tools/testing/selftests/bpf

# kfunc extern protos are mirrored from kernel BTF by add_ksyms.py
# (vmlinux first = base BTF, then the test kmods' split BTFs).
BPFTOOL_BIN := $(dir $(SELFTESTS_OUTPUT))bpftool-output-$(patsubst selftests-output-%,%,$(notdir $(SELFTESTS_OUTPUT)))/bpftool
KSYM_BTF_FILES := $(VMLINUX_BTF) $(wildcard $(SELFTESTS_OUTPUT)/*.ko)
RUSTBPF ?= $(abspath $(CURDIR)/../rust-bpf)
LLVM_PREFIX ?= $(abspath $(CURDIR)/../uml-harness/.build/llvm-install)
UML_HARNESS ?= $(abspath $(CURDIR)/../uml-harness)
UML_INSTALL_DIR ?= $(HOME)/.local/share/uml-veristat-heimdall

BLDDIR := $(CURDIR)/bld
LLC := $(LLVM_PREFIX)/bin/llc
OPT := $(LLVM_PREFIX)/bin/opt
LLVM_LINK := $(LLVM_PREFIX)/bin/llvm-link
LLVM_AS := $(LLVM_PREFIX)/bin/llvm-as
LLVM_DIS := $(LLVM_PREFIX)/bin/llvm-dis
LLVM_OBJCOPY := $(LLVM_PREFIX)/bin/llvm-objcopy
LLVM_READELF := $(LLVM_PREFIX)/bin/llvm-readelf
TARGET := $(RUSTBPF)/bpfel-unknown-none-v4.json
DEPDIR := $(RUSTBPF)/bld_deps
BPF_POSTPROC := $(RUSTBPF)/bld/bpf-postproc
BTF_MACROS := $(RUSTBPF)/bld/libbtf_macros.so

RUSTC ?= rustc
RUST_SRC ?= $(shell $(RUSTC) --print sysroot)/lib/rustlib/src/rust/library

RUSTFLAGS_ENV := RUSTC_BOOTSTRAP=1
RUSTC_COMMON := --target $(TARGET) -C opt-level=3 -C panic=unwind -C debuginfo=2 -Z unstable-options -Z threads=64

PROGS := $(patsubst progs/%.rs,%,$(wildcard progs/*.rs))

export KERNEL_SRC SELFTESTS_SRC SELFTESTS_OUTPUT LLVM_PREFIX UML_HARNESS UML_INSTALL_DIR

all: $(addprefix $(BLDDIR)/,$(addsuffix .bpf.o,$(PROGS)))

# --- Keep-list: the global FUNC/OBJECT symbols of the C-built object are the
# --- ABI the harness sees; keep exactly those through internalize/globaldce.
$(BLDDIR)/%.keep: $(SELFTESTS_OUTPUT)/%.bpf.o.corig
	@mkdir -p $(BLDDIR)
	$(LLVM_READELF) -s $< | \
		awk '$$4 ~ /FUNC|OBJECT/ && $$5 == "GLOBAL" && $$7 != "UND" {print $$8}' | \
		sort -u > $@

# The .corig backup of the pristine C object is created on first use.
$(SELFTESTS_OUTPUT)/%.bpf.o.corig:
	cp $(SELFTESTS_OUTPUT)/$*.bpf.o $@

# --- Support crate: header-only by construction (macros/generics/inline),
# --- so its bodies monomorphize into each program's bitcode and the
# --- link/postproc pipeline is unchanged.
$(BLDDIR)/libbpf_rs_core.rlib: $(wildcard bpf-rs-core/src/*.rs)
	@mkdir -p $(BLDDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--crate-name bpf_rs_core \
		-o $@ bpf-rs-core/src/lib.rs

# --- Rust -> LLVM bitcode ---
$(BLDDIR)/%.bc: progs/%.rs $(BLDDIR)/libbpf_rs_core.rlib
	@mkdir -p $(BLDDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--extern btf=$(DEPDIR)/libbtf.rlib \
		--extern btf_macros=$(BTF_MACROS) \
		--extern bpf_rs_core=$(BLDDIR)/libbpf_rs_core.rlib \
		-Zcrate-attr='feature(alloc_error_handler)' \
		--crate-name $* \
		--emit=llvm-bc -o $@ $<

# --- Link with libcore/liballoc/intrinsics ---
$(BLDDIR)/%-linked.bc: $(BLDDIR)/%.bc
	@cp $< $@
	@for i in 1 2 3 4 5; do \
		$(LLVM_LINK) --only-needed $@ \
			$$(find $(DEPDIR)/extracted -name '*.rcgu.o') \
			-o $@.tmp && mv $@.tmp $@; \
	done
	@$(LLVM_LINK) $@ $(DEPDIR)/multi3.bc -o $@.tmp && mv $@.tmp $@

# --- Lower btf polyfills to CO-RE relocations ---
$(BLDDIR)/%-reloc.bc: $(BLDDIR)/%-linked.bc
	$(BPF_POSTPROC) $< $@

# --- Internalize (keep = C object ABI) + optimize ---
$(BLDDIR)/%-opt.bc: $(BLDDIR)/%-reloc.bc $(BLDDIR)/%.keep
	$(OPT) $$(sed 's/^/--internalize-public-api-list=/' $(BLDDIR)/$*.keep | tr '\n' ' ') \
		--force-remove-attribute=cold \
		-passes='forceattrs,internalize,globaldce,default<O2>' $< -o $@

# --- invoke->call, unreachable->ret, .ksyms ---
$(BLDDIR)/%-ksyms.bc: $(BLDDIR)/%-opt.bc
	$(LLVM_DIS) $< -o $@.ll
	KSYM_BTF_FILES="$(KSYM_BTF_FILES)" BPFTOOL="$(BPFTOOL_BIN)" \
		python3 $(RUSTBPF)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@.tmp.bc
	$(OPT) -passes=simplifycfg $@.tmp.bc -o $@.tmp2.bc
	$(LLVM_DIS) $@.tmp2.bc -o $@.ll
	KSYM_BTF_FILES="$(KSYM_BTF_FILES)" BPFTOOL="$(BPFTOOL_BIN)" \
		python3 $(RUSTBPF)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@
	@rm -f $@.ll $@.tmp.bc $@.tmp2.bc

# --- Final BPF object ---
$(BLDDIR)/%.bpf.o: $(BLDDIR)/%-ksyms.bc
	$(LLC) -march=bpfel -mcpu=v4 -filetype=obj -o $@.tmp $<
	$(LLVM_OBJCOPY) \
		--remove-section=.eh_frame --remove-section=.rel.eh_frame \
		--remove-section=.gcc_except_table \
		--strip-symbol=rust_eh_personality $@.tmp $@
	@rm -f $@.tmp
	python3 scripts/btf_rename.py $@

# --- Kernel verifier gate (all built objects) ---
verify: all
	UML_INSTALL_DIR=$(UML_INSTALL_DIR) $(UML_HARNESS)/uml-veristat \
		$(addprefix $(BLDDIR)/,$(addsuffix .bpf.o,$(PROGS)))

# --- Swap Rust object in, rebuild harness pieces, run affected tests in UML ---
test-%: $(BLDDIR)/%.bpf.o
	scripts/swap-and-test.sh $* rust

# --- Put the C original back and rebuild harness pieces ---
restore-%:
	scripts/swap-and-test.sh $* c

echo-kernel-src:
	@echo $(KERNEL_SRC)

status:
	@total=$$(ls $(SELFTESTS_SRC)/progs/*.c | wc -l); \
	done=$$(ls progs/*.rs 2>/dev/null | wc -l); \
	echo "translated $$done of $$total kernel selftests BPF programs:"; \
	for p in $(PROGS); do echo "  $$p"; done

clean:
	rm -rf $(BLDDIR)

.PRECIOUS: $(BLDDIR)/%.bc $(BLDDIR)/%-linked.bc $(BLDDIR)/%-reloc.bc \
           $(BLDDIR)/%-opt.bc $(BLDDIR)/%-ksyms.bc $(BLDDIR)/%.keep \
           $(SELFTESTS_OUTPUT)/%.bpf.o.corig

.PHONY: all verify status clean

# --- equivalence regression guard + translation linter ---
PYZ3 ?= $(abspath $(CURDIR)/../z3-venv/bin/python)
equiv-guard:
	$(PYZ3) equiv/guard.py

translint:
	python3 scripts/translint.py

.PHONY: equiv-guard translint

# --- Undo any swapped-in Rust objects (make test-<name> leaves the Rust
# --- object in the selftests slot; comparing against it would be
# --- Rust-vs-Rust). Safe to run any time.
restore-all:
	@n=0; for f in $(SELFTESTS_OUTPUT)/*.bpf.o.corig; do \
		b=$${f%.corig}; \
		cmp -s "$$b" "$$f" || { cp "$$f" "$$b"; n=$$((n+1)); }; \
	done; echo "restored $$n C object(s)"

.PHONY: restore-all

# --- CI ---
# ci-fast: the hermetic tier, identical to what GitHub Actions runs.
ci-fast:
	$(PYZ3) -m pytest equiv/tests -q
	python3 -m compileall -q equiv scripts
	$(PYZ3) equiv/gendoc.py --check
	@echo "hermetic checks OK"

# Regenerate the BPF->Z3 semantics document from the live lifter.
semantics:
	$(PYZ3) equiv/gendoc.py

# ci-local: everything that needs the pinned kernel tree and built objects.
# Order matters — undo any swapped-in objects BEFORE proving, or the
# comparison is Rust-vs-Rust.
ci-local: restore-all ci-fast
	python3 scripts/translint.py || true
	$(PYZ3) equiv/guard.py

.PHONY: ci-fast ci-local semantics
