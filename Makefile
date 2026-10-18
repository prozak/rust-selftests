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
#   make verify          run all built objects through the kernel verifier
#                        (UML flavor only)
#   make test-<name>     swap Rust object into the selftests output, regenerate
#                        skeletons + test_progs via the kernel Makefile, run the
#                        affected test(s) in the guest
#   make restore-<name>  put the original C object back and rebuild harness
#   make status          translation coverage vs the kernel progs/ directory
#
# Configuration (override via environment or command line):
#   BUILD_DIR         root of the QEMU build tree (default .build/); the
#                     defaults below hang off it (see scripts/paths.sh)
#   KERNEL_SRC        bpf-next checkout (with built selftests)
#   SELFTESTS_OUTPUT  the selftests build output directory (contains *.bpf.o,
#                     test_progs, generated skeletons)
#   RUSTBPF           4ast/rust-bpf checkout with built bld_deps/ and tools,
#                     with pull request #6 (btf_tags.py) merged
#   LLVM_PREFIX       LLVM 23 install (scripts/build-llvm.sh; llc/opt/llvm-link/...)
#   UML_HARNESS       uml-veristat checkout (uml-veristat/uml-test-progs;
#                     FLAVOR=uml only)
#   UML_INSTALL_DIR   uml-veristat install to boot (FLAVOR=uml only)

# FLAVOR selects the oracle. qemu (the default): the x86_64 worktree pinned
# by kernel-commit, booted by virtme-ng/KVM. uml: the parked UML branch
# (older pin, patched kernel, reduced feature set) -- only when asked for
# explicitly.
FLAVOR ?= qemu
BUILD_DIR ?= $(CURDIR)/.build
ifeq ($(FLAVOR),qemu)
KERNEL_SRC ?= $(BUILD_DIR)/bpf-next
SELFTESTS_OUTPUT ?= $(BUILD_DIR)/selftests-output-qemu
VMLINUX_BTF ?= $(KERNEL_SRC)/vmlinux
QEMU_KERNEL ?= $(KERNEL_SRC)/arch/x86/boot/bzImage
TEST_RUNNER ?= $(CURDIR)/scripts/qemu-test-progs
LLVM_PREFIX ?= $(BUILD_DIR)/llvm
else ifeq ($(FLAVOR),uml)
KERNEL_SRC ?= $(abspath $(CURDIR)/../uml-harness/.build/bpf-next)
SELFTESTS_OUTPUT ?= $(abspath $(CURDIR)/../uml-harness/.build/selftests-output-heimdall)
VMLINUX_BTF ?= $(KERNEL_SRC)/linux
UML_HARNESS ?= $(abspath $(CURDIR)/../uml-harness)
UML_INSTALL_DIR ?= $(HOME)/.local/share/uml-veristat-heimdall
TEST_RUNNER ?= $(UML_HARNESS)/uml-test-progs
LLVM_PREFIX ?= $(abspath $(CURDIR)/../uml-harness/.build/llvm-install)
else
$(error unknown FLAVOR '$(FLAVOR)' (qemu or uml))
endif
export FLAVOR BUILD_DIR VMLINUX_BTF QEMU_KERNEL TEST_RUNNER UML_HARNESS UML_INSTALL_DIR
SELFTESTS_SRC := $(KERNEL_SRC)/tools/testing/selftests/bpf

# The bpf-next commit the QEMU flavor kernel is built from. The worktree is
# that commit plus exactly the patches vendored in patches/kernel/ (none, if
# the directory is empty), so check-kernel-commit fails as soon as either
# side moves alone.
KERNEL_COMMIT := $(shell cat $(CURDIR)/kernel-commit)

# kfunc extern protos are mirrored from kernel BTF by add_ksyms.py
# (vmlinux first = base BTF, then the test kmods' split BTFs).
BPFTOOL_BIN := $(dir $(SELFTESTS_OUTPUT))bpftool-output-$(patsubst selftests-output-%,%,$(notdir $(SELFTESTS_OUTPUT)))/bpftool
KSYM_BTF_FILES := $(VMLINUX_BTF) $(wildcard $(SELFTESTS_OUTPUT)/*.ko)
RUSTBPF ?= $(abspath $(CURDIR)/../rust-bpf)

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
OPT_LEVEL ?= 3
# --remap-path-prefix: the objects embed the source paths (BTF line info,
# .debug_str), and the baselines are keyed by object hash; without it the
# same sources hash differently in every checkout (a worktree, say).
RUSTC_COMMON := --target $(TARGET) -C opt-level=$(OPT_LEVEL) -C panic=unwind -C debuginfo=2 \
	-Z unstable-options -Z threads=64 --remap-path-prefix=$(CURDIR)=/rust-selftests

PROGS := $(patsubst progs/%.rs,%,$(wildcard progs/*.rs))

# RUSTBPF too: the drivers (ci_nightly.py, gate.py) run make again.
export KERNEL_SRC SELFTESTS_SRC SELFTESTS_OUTPUT LLVM_PREFIX RUSTBPF

all: $(addprefix $(BLDDIR)/,$(addsuffix .bpf.o,$(PROGS))) $(BLDDIR)/vmlinux.btf

# Raw kernel BTF for the equivalence checker (CO-RE target, kfunc protos):
# much faster to load than vmlinux, and tied to it so a rebuilt kernel
# cannot leave a stale copy behind.
# The explicit empty rule matters: without it `make -B` applies the
# built-in "link % from %.o" rule to the kernel image and deletes it.
$(VMLINUX_BTF): ;
$(BLDDIR)/vmlinux.btf: $(VMLINUX_BTF)
	@mkdir -p $(BLDDIR)
	$(LLVM_OBJCOPY) --dump-section=.BTF=$@.tmp $< /dev/null && mv $@.tmp $@

# --- Keep-list: the global and weak FUNC/OBJECT symbols of the C-built object
# --- are the ABI the harness sees (a `__weak` function is a global subprogram
# --- to libbpf and the verifier); keep exactly those through internalize/
# --- globaldce.
# The prerequisite is the installed object, which always exists, but the
# symbols are read from the pristine .corig backup when a swap has put the
# Rust object in its place. It used to depend on the .corig alone: that file
# is an intermediate with no prerequisites, so once a fresh selftests output
# had no backups make treated every stale keep as up to date and a program
# the C object gained after the bump was internalized and dropped. The keep
# is only replaced when its content changes, so a swap/restore (which bumps
# the object's mtime) does not rebuild the translation. Static pattern rule
# rather than a plain one: a keep matched only by a pattern is an
# intermediate file, and make does not recreate a missing intermediate
# unless its prerequisite is newer than the final object.
KEEPS := $(addprefix $(BLDDIR)/,$(addsuffix .keep,$(PROGS)))
$(KEEPS): $(BLDDIR)/%.keep: $(SELFTESTS_OUTPUT)/%.bpf.o
	@mkdir -p $(BLDDIR)
	@src=$<; [ -f $<.corig ] && src=$<.corig; \
	$(LLVM_READELF) -s $$src | \
		awk '$$4 ~ /FUNC|OBJECT/ && $$5 ~ /GLOBAL|WEAK/ && $$7 != "UND" {print $$8}' | \
		sort -u > $@.tmp; \
	if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; echo "[keep] $*: $$(tr '\n' ' ' < $@)"; fi

# --- Support crate: header-only by construction (macros/generics/inline),
# --- so its bodies monomorphize into each program's bitcode and the
# --- link/postproc pipeline is unchanged.
# The rlib records the hash of the btf crate it was built against; a
# rust-bpf checkout with a different libbtf.rlib makes it unusable.
$(BLDDIR)/libbpf_rs_core.rlib: $(wildcard bpf-rs-core/src/*.rs) $(DEPDIR)/libbtf.rlib
	@mkdir -p $(BLDDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		--sysroot=/dev/null -L$(DEPDIR) \
		--crate-name bpf_rs_core \
		-o $@ bpf-rs-core/src/lib.rs

# --- Rust -> LLVM bitcode ---
$(BLDDIR)/ksock_lsm.bc $(BLDDIR)/ksock_wq.bc: progs/common/ksock.rs
$(BLDDIR)/arena_kfunc.bc $(BLDDIR)/arena_kfunc_jit.bc $(BLDDIR)/struct_ops_arena.bc: progs/common/arena.rs
# The hand-translated C bodies a generated verifier_* translation include!s
# (scripts/naked_gen.py --with-c-bodies).
$(foreach h,$(wildcard progs/hand/*.rs),$(eval $(BLDDIR)/$(notdir $(h:.rs=)).bc: $(h)))
# `// RUSTC_OPT_LEVEL: <0-3|s|z>` in a translation overrides OPT_LEVEL for
# that one object (the later -C opt-level wins): for a loop whose verifier
# cost depends on the exact code shape (pyperf600_nounroll).
$(BLDDIR)/%.bc: progs/%.rs $(BLDDIR)/libbpf_rs_core.rlib
	@mkdir -p $(BLDDIR)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) \
		$$(sed -n 's|^// RUSTC_OPT_LEVEL: \([0-3sz]\)\s*$$|-C opt-level=\1|p' progs/$*.rs) \
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
KSYM_VAR_SRCS := $(shell grep -l '^// BTF_KSYM:' progs/*.rs)
$(patsubst progs/%.rs,$(BLDDIR)/%-opt.bc,$(KSYM_VAR_SRCS)): scripts/ksym_vars.py
TYPE_ID_SRCS := $(shell grep -l '^// BTF_TYPE_ID:' progs/*.rs)
$(patsubst progs/%.rs,$(BLDDIR)/%-opt.bc,$(TYPE_ID_SRCS)): scripts/type_id.py
# `// BTF_WEAK_KFUNC: name` marks a kfunc the C declares `__ksym __weak` (one
# that may not exist in the running kernel, like test_ksyms_weak.c's
# invalid_kfunc): rustc ignores #[linkage = "extern_weak"] on a foreign
# function, so the object rule weakens the undefined symbol with
# llvm-objcopy, and libbpf then treats the missing kfunc as optional.
# usdt.bpf.h's weak maps are ABI exports even though the handler does not
# reference them (the keep list has them as WEAK OBJECTs too; this predates
# the keep list's weak symbols and is kept as belt and braces).
$(BLDDIR)/uprobe_multi_usdt-opt.bc: Makefile
$(BLDDIR)/uprobe_multi_usdt-opt.bc: PUBLIC_API_EXTRA = --internalize-public-api-list=__bpf_usdt_specs,__bpf_usdt_ip_to_spec_id

$(BLDDIR)/%-opt.bc: $(BLDDIR)/%-reloc.bc $(BLDDIR)/%.keep
	@set -e; src=$<; \
	if grep -q '^// BTF_KSYM:' progs/$*.rs; then \
		$(LLVM_DIS) $$src -o $@.ksyms.ll; \
		python3 scripts/ksym_vars.py $@.ksyms.ll progs/$*.rs $(SELFTESTS_OUTPUT)/$*.bpf.o; \
		src=$@.ksyms.ll; \
	fi; \
	if grep -q '^// BTF_TYPE_ID:' progs/$*.rs; then \
		if [ "$$src" = "$<" ]; then $(LLVM_DIS) $$src -o $@.types.ll; \
		else cp $$src $@.types.ll; fi; \
		python3 scripts/type_id.py $@.types.ll progs/$*.rs $(SELFTESTS_OUTPUT)/$*.bpf.o; \
		src=$@.types.ll; \
	fi; \
	$(OPT) $(PUBLIC_API_EXTRA) $$(sed 's/^/--internalize-public-api-list=/' $(BLDDIR)/$*.keep | tr '\n' ' ') \
		--force-remove-attribute=cold \
		-passes='forceattrs,internalize,globaldce,default<O2>' $$src -o $@; \
	rm -f $@.ksyms.ll $@.types.ll

# --- invoke->call, unreachable->ret, .ksyms, #[btf_tag] annotations ---
# btf_tags.py (rust-bpf PR #6) runs last, as in rust-bpf's own Makefile: it
# turns the `.btf_tags` manifest that #[btf_tag] leaves in the IR into
# debug-info annotations, from which llc emits BTF decl and type tags.
$(BLDDIR)/%-ksyms.bc: $(BLDDIR)/%-opt.bc $(RUSTBPF)/btf_tags.py
	$(LLVM_DIS) $< -o $@.ll
	KSYM_BTF_FILES="$(KSYM_BTF_FILES)" BPFTOOL="$(BPFTOOL_BIN)" \
		python3 $(RUSTBPF)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@.tmp.bc
	$(OPT) -passes=simplifycfg $@.tmp.bc -o $@.tmp2.bc
	$(LLVM_DIS) $@.tmp2.bc -o $@.ll
	KSYM_BTF_FILES="$(KSYM_BTF_FILES)" BPFTOOL="$(BPFTOOL_BIN)" \
		python3 $(RUSTBPF)/add_ksyms.py $@.ll $@.ll
	python3 $(RUSTBPF)/btf_tags.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@
	@rm -f $@.ll $@.tmp.bc $@.tmp2.bc

# An explicit rule, so a rust-bpf checkout without the pull request says
# what is wrong instead of make's "No rule to make target". The test is in
# the recipe, not $(error): under `make -B` every recipe runs, the file's
# presence notwithstanding.
$(RUSTBPF)/btf_tags.py:
	@[ -f $@ ] || { echo "$@ is missing: rust-selftests needs rust-bpf with pull request #6 (the btf_tag attribute) merged, see README" >&2; exit 1; }

# --- Final BPF object ---
# -relocation-model=static, as clang's BPF target defaults to: under llc's
# PIC default a read-only table of function pointers (verifier_callx_rodata)
# is "read-only with relocations", a writable .data.rel.ro section, where
# the C object has it in .rodata.
ORDER_SRCS := $(shell grep -l '^// BPF_PROGRAM_ORDER:' progs/*.rs)
$(patsubst progs/%.rs,$(BLDDIR)/%.bpf.o,$(ORDER_SRCS)): scripts/program_order.py
$(BLDDIR)/%.bpf.o: $(BLDDIR)/%-ksyms.bc scripts/naked_abi.py scripts/btf_graph_types.py scripts/private_sections.py \
		scripts/maps_section.py scripts/btf_rename.py scripts/btf_map_slots.py scripts/btf_fn_ptrs.py scripts/btf_test_tags.py scripts/btf_type_tags.py scripts/btf_anon.py \
		scripts/stack_args.py
	$(LLVM_DIS) $< -o $@.abi.ll
	python3 scripts/naked_abi.py $@.abi.ll progs/$*.rs
	python3 scripts/stack_args.py $@.abi.ll
	python3 scripts/btf_graph_types.py $@.abi.ll
	python3 scripts/private_sections.py $@.abi.ll $(SELFTESTS_OUTPUT)/$*.bpf.o \
		$$(sed -n 's|^// C_LAYOUT: ||p' progs/$*.rs | tr ' ' '\n' | sed 's|^|--layout=|')
	@if grep -q '^// BPF_PROGRAM_ORDER:' progs/$*.rs; then python3 scripts/program_order.py $@.abi.ll progs/$*.rs; fi
	python3 scripts/maps_section.py $@.abi.ll
	$(LLC) -march=bpfel -mcpu=v4 -relocation-model=static -filetype=obj -o $@.tmp $@.abi.ll
	$(LLVM_OBJCOPY) \
		--remove-section=.eh_frame --remove-section=.rel.eh_frame \
		--remove-section=.gcc_except_table \
		--strip-symbol=rust_eh_personality \
		$$(sed -n 's|^// BTF_WEAK_KFUNC: \([A-Za-z_][A-Za-z_0-9]*\)\s*$$|--weaken-symbol=\1|p' progs/$*.rs) \
		$@.tmp $@
	@rm -f $@.tmp $@.abi.ll
	python3 scripts/btf_rename.py $@ progs/$*.rs
	python3 scripts/btf_map_slots.py $@
	@if grep -q '^// BTF_FN_PTR:' progs/$*.rs; then python3 scripts/btf_fn_ptrs.py $@ progs/$*.rs; fi
	@if grep -q '^// BTF_ANON$$' progs/$*.rs; then python3 scripts/btf_anon.py $@; fi
	python3 scripts/btf_test_tags.py $@ progs/$*.rs
	python3 scripts/btf_type_tags.py $@ progs/$*.rs

# --- Kernel verifier gate (all built objects), UML flavor only ---
# Objects a translation declares must FAIL to load (test_tags! __failure) are
# left out: the verifier rejecting them is the assertion, not a regression.
# Under the QEMU flavor the acceptance gate is test-<name> itself.
verify: all
	@[ "$(FLAVOR)" = uml ] || { echo "verify runs uml-veristat: FLAVOR=uml make verify" >&2; exit 1; }
	@neg=$$(python3 scripts/btf_test_tags.py --list-negative progs/*.rs); \
	[ -z "$$neg" ] || echo "[verify] skipping must-fail object(s): $$(echo $$neg)"; \
	objs=""; for n in $(PROGS); do \
		echo "$$neg" | grep -qx "$$n" || objs="$$objs $(BLDDIR)/$$n.bpf.o"; \
	done; \
	UML_INSTALL_DIR=$(UML_INSTALL_DIR) $(UML_HARNESS)/uml-veristat $$objs

# --- Swap Rust object in, rebuild harness pieces, run affected tests in the guest ---
test-%: $(BLDDIR)/%.bpf.o
	scripts/swap-and-test.sh $* rust

# --- Put the C original back and rebuild harness pieces ---
restore-%:
	scripts/swap-and-test.sh $* c

echo-kernel-src:
	@echo $(KERNEL_SRC)

echo-pyz3:
	@echo $(PYZ3)

check-kernel-commit:
	@[ "$(FLAVOR)" = qemu ] || { echo "check-kernel-commit: QEMU flavor only" >&2; exit 1; }; \
	npatch=$$(ls patches/kernel/*.patch 2>/dev/null | wc -l); \
	git -C $(KERNEL_SRC) merge-base --is-ancestor $(KERNEL_COMMIT) HEAD 2>/dev/null && \
	have=$$(git -C $(KERNEL_SRC) rev-list --count $(KERNEL_COMMIT)..HEAD) && \
	[ "$$have" = "$$npatch" ] || { \
	  echo "kernel-commit: $(KERNEL_SRC) is not $(KERNEL_COMMIT) plus the" \
	       "$$npatch patch(es) in patches/kernel/" >&2; exit 1; }

status: check-kernel-commit
	@echo "kernel: bpf-next $(KERNEL_COMMIT) + $$(ls patches/kernel/*.patch 2>/dev/null | wc -l) patch(es) from patches/kernel/"; \
	total=$$(ls $(SELFTESTS_SRC)/progs/*.c | wc -l); \
	done=$$(ls progs/*.rs 2>/dev/null | wc -l); \
	echo "translated $$done of $$total kernel selftests BPF programs:"; \
	for p in $(PROGS); do echo "  $$p"; done; \
	echo "Excluded fixtures/configurations (not translation targets):"; \
	while IFS=$$(printf '\t') read -r name reason; do \
	  case "$$name" in \#*|"") continue ;; esac; \
	  [ ! -f "$(SELFTESTS_SRC)/progs/$$name.c" ] || printf '  %s: %s\n' "$$name" "$$reason"; \
	done < scripts/non-targets.tsv

clean:
	rm -rf $(BLDDIR)

.PRECIOUS: $(BLDDIR)/%.bc $(BLDDIR)/%-linked.bc $(BLDDIR)/%-reloc.bc \
           $(BLDDIR)/%-opt.bc $(BLDDIR)/%-ksyms.bc $(BLDDIR)/%.keep \
           $(SELFTESTS_OUTPUT)/%.bpf.o.corig

.PHONY: all verify status check-kernel-commit clean

# --- equivalence regression guard + translation linter ---
# Python with z3-solver and pytest (pip install -r requirements.txt); a
# virtualenv at .venv/ is picked up automatically.
PYZ3 ?= $(if $(wildcard $(CURDIR)/.venv/bin/python),$(CURDIR)/.venv/bin/python,python3)
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
		[ -f "$$f" ] || continue; \
		b=$${f%.corig}; \
		cmp -s "$$b" "$$f" || { cp "$$f" "$$b" || exit 1; n=$$((n+1)); }; \
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

# gate: the QEMU verifier/runtime gate over what changed since the
# committed qemu/gate/baseline.tsv (scripts/gate.py; seconds when nothing
# did). GATE_WORKERS guests run at once, each over a private overlay of the
# selftests output; it restores the C objects first and last.
GATE_WORKERS ?= 8
gate:
	$(PYZ3) scripts/gate.py --workers $(GATE_WORKERS)

# ci-local: everything that needs the pinned kernel tree and built objects.
# Order matters — undo any swapped-in objects BEFORE proving, or the
# comparison is Rust-vs-Rust; the gate swaps objects, so it comes after
# the proof and restores them itself.
ci-local: restore-all ci-fast check-kernel-commit $(BLDDIR)/vmlinux.btf
	python3 scripts/translint.py
	$(PYZ3) equiv/guard.py
	$(PYZ3) scripts/gate.py --workers $(GATE_WORKERS)

.PHONY: ci-fast ci-local gate semantics

# Fresh whole-corpus validation on the pinned QEMU stack. The Python driver
# sequences recursive make calls even when the caller supplies -j.
NIGHTLY_JOBS ?= 8
NIGHTLY_BUILD_JOBS ?= 4
NIGHTLY_GATE_WORKERS ?= 8
NIGHTLY_OUT ?=
ci-nightly:
	$(PYZ3) scripts/ci_nightly.py --jobs $(NIGHTLY_JOBS) --build-jobs $(NIGHTLY_BUILD_JOBS) \
		--gate-workers $(NIGHTLY_GATE_WORKERS) $(if $(NIGHTLY_OUT),--out "$(NIGHTLY_OUT)")

# The gate workers' private state under $(BUILD_DIR)/gate: overlay upper
# dirs (tens of MB each) or, in copy mode, whole output trees (~0.7 GB each).
clean-gate-workers:
	scripts/gate-workers.sh --clean

.PHONY: ci-nightly clean-gate-workers

# --- codegen study: what rustc emits vs clang, over proved-equivalent pairs
codegen:
	$(PYZ3) codegen/compare.py

.PHONY: codegen
