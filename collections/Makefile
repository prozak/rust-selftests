# Real Rust `alloc` collections in BPF, backed by a BPF arena through
# libarena's buddy allocator (vendored as a git submodule under vendor/).
#
# Pipeline (bitcode-level merge — one object, one BTF):
#   clang  vendor/libarena/{common,buddy}.bpf.c + glue/  -> .bc
#   rustc  arena-alloc (GlobalAlloc over arena_malloc_internal)  -> rlib
#   rustc  progs/<name>.rs  -> .bc
#   llvm-link  prog.bc + arena .bcs, then --only-needed libcore/liballoc
#   opt O2, add_ksyms.py (invoke->call etc.), llc -mcpu=v4, btf_rename
#
# Run: make test  (boots the qemu kernel via vng, runs loader against every
# built object; each SEC("syscall") test_* program must return 0).

HEIM     := $(abspath ../..)
RUSTBPF  ?= $(HEIM)/rust-bpf
LLVM     := $(HEIM)/uml-harness/.build/llvm-install/bin
BTOOLDIR := $(HEIM)/uml-harness/.build/bpftool-output-qemu
KERNEL   := $(HEIM)/uml-harness/.build/bpf-next-x86
DEPDIR   := $(RUSTBPF)/bld_deps
TARGET   := $(RUSTBPF)/bpfel-unknown-none-v4.json

CLANG        := $(LLVM)/clang
LLC          := $(LLVM)/llc
OPT          := $(LLVM)/opt
LLVM_LINK    := $(LLVM)/llvm-link
LLVM_AS      := $(LLVM)/llvm-as
LLVM_DIS     := $(LLVM)/llvm-dis
LLVM_OBJCOPY := $(LLVM)/llvm-objcopy
RUSTC        ?= rustc
CC           ?= cc

LA  := vendor/libarena/libarena
BLD := bld

RUSTFLAGS_ENV := RUSTC_BOOTSTRAP=1
RUSTC_COMMON  := --target $(TARGET) -C opt-level=3 -C panic=unwind -C debuginfo=2 \
                 -Z unstable-options -Z threads=64

BPF_CFLAGS := --target=bpfel -mcpu=v4 -O2 -g -DENABLE_ATOMICS_TESTS \
              -Wno-incompatible-pointer-types-discards-qualifiers \
              -Wno-missing-declarations -Wno-macro-redefined \
              -I$(LA)/include -I$(BTOOLDIR) -I$(BTOOLDIR)/libbpf/include

ARENA_BCS := $(BLD)/arena_common.bc $(BLD)/arena_buddy.bc $(BLD)/arena_glue.bc
PROGS     := $(patsubst progs/%.rs,%,$(wildcard progs/*.rs))

# Local libcore/liballoc built with panic_immediate_abort: collection
# internals (BTreeMap node slicing, RawVec growth) contain panic paths, and
# the standard build's panic formatting (core::fmt pad_integral) cannot be
# lowered by the BPF backend (6-arg calls, stack arguments). With
# panic_immediate_abort every panic becomes a plain abort — no fmt at all.
# Kept separate from rust-bpf/bld_deps so the 550-translation pipeline's
# bitcode is unaffected.
PIA      := $(BLD)/deps
RUST_SRC ?= $(shell $(RUSTC) --print sysroot)/lib/rustlib/src/rust/library
PIA_PANIC := -C panic=immediate-abort

all: $(addprefix $(BLD)/,$(addsuffix .bpf.o,$(PROGS))) $(BLD)/loader

$(PIA)/libcore.rlib: $(RUST_SRC)/core/src/lib.rs
	@mkdir -p $(PIA)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) $(PIA_PANIC) \
		--sysroot=/dev/null \
		--cfg 'no_fp_fmt_parse' \
		--crate-name core \
		--emit=link=$@ --emit=metadata=$(PIA)/libcore.rmeta \
		$<

$(PIA)/libcompiler_builtins.rlib: $(PIA)/libcore.rlib
	echo '#![no_std]' '#![feature(compiler_builtins,rustc_attrs)]' '#![compiler_builtins]' '#![allow(internal_features)]' '#[rustc_std_internal_symbol] fn __rust_no_alloc_shim_is_unstable_v2() {}' | \
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) $(PIA_PANIC) \
		--sysroot=/dev/null -L$(PIA) \
		--crate-name compiler_builtins \
		--emit=link=$@ --emit=metadata=$(PIA)/libcompiler_builtins.rmeta \
		-

$(PIA)/liballoc.rlib: $(RUST_SRC)/alloc/src/lib.rs $(PIA)/libcompiler_builtins.rlib
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) $(PIA_PANIC) \
		--sysroot=/dev/null -L$(PIA) \
		--crate-name alloc \
		--emit=link=$@ --emit=metadata=$(PIA)/liballoc.rmeta \
		$<

$(PIA)/extracted: $(PIA)/libcore.rlib $(PIA)/libcompiler_builtins.rlib $(PIA)/liballoc.rlib
	@rm -rf $@ && mkdir -p $@/core $@/compiler_builtins $@/alloc
	cd $(PIA)/extracted/core && $(LLVM)/llvm-ar x ../../libcore.rlib && rm -f lib.rmeta
	cd $(PIA)/extracted/compiler_builtins && $(LLVM)/llvm-ar x ../../libcompiler_builtins.rlib && rm -f lib.rmeta
	cd $(PIA)/extracted/alloc && $(LLVM)/llvm-ar x ../../liballoc.rlib && rm -f lib.rmeta

# --- libarena C -> bitcode ---
$(BLD)/arena_%.bc: $(LA)/src/%.bpf.c
	@mkdir -p $(BLD)
	$(CLANG) $(BPF_CFLAGS) -emit-llvm -c $< -o $@

$(BLD)/arena_glue.bc: glue/arena_glue.bpf.c
	@mkdir -p $(BLD)
	$(CLANG) $(BPF_CFLAGS) -emit-llvm -c $< -o $@

# --- allocator crate (rlib for rustc metadata + extracted bitcode for the
# --- llvm-link step: its symbols — GlobalAlloc impl, panic/oom handlers —
# --- are real code, unlike the header-only bpf-rs-core) ---
$(BLD)/libarena_alloc.rlib: arena-alloc/src/lib.rs $(PIA)/libcompiler_builtins.rlib
	@mkdir -p $(BLD)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) $(PIA_PANIC) \
		--sysroot=/dev/null -L$(PIA) \
		-Zcrate-attr='feature(alloc_error_handler)' \
		--crate-name arena_alloc \
		-o $@ $<
	@rm -rf $(BLD)/arena_alloc_cgu && mkdir -p $(BLD)/arena_alloc_cgu
	cd $(BLD)/arena_alloc_cgu && $(LLVM)/llvm-ar x ../../$@ && rm -f lib.rmeta

# --- program -> bitcode ---
$(BLD)/%.bc: progs/%.rs $(BLD)/libarena_alloc.rlib $(PIA)/liballoc.rlib
	@mkdir -p $(BLD)
	$(RUSTFLAGS_ENV) $(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) $(PIA_PANIC) \
		--sysroot=/dev/null -L$(PIA) \
		--extern alloc=$(PIA)/liballoc.rlib \
		--extern arena_alloc=$(BLD)/libarena_alloc.rlib \
		--crate-name $* \
		--emit=llvm-bc -o $@ $<

# --- merge Rust + libarena, then pull in libcore/liballoc as needed ---
$(BLD)/%-linked.bc: $(BLD)/%.bc $(ARENA_BCS) $(PIA)/extracted $(BLD)/multi3-inline.bc
	$(LLVM_LINK) $< $(ARENA_BCS) $$(find $(BLD)/arena_alloc_cgu -name '*.rcgu.o') -o $@
	@for i in 1 2 3 4 5; do \
		$(LLVM_LINK) --only-needed $@ \
			$$(find $(PIA)/extracted -name '*.rcgu.o') \
			-o $@.tmp && mv $@.tmp $@; \
	done
	@$(LLVM_LINK) $@ $(BLD)/multi3-inline.bc -o $@.tmp && mv $@.tmp $@

# alloc's checked layout arithmetic genuinely calls __multi3 here; an
# out-of-line i128-ABI function cannot be compiled by the BPF backend, so
# force it to inline into every caller (the standalone def then dies in
# globaldce).
$(BLD)/multi3-inline.bc: $(RUSTBPF)/multi3.ll
	@mkdir -p $(BLD)
	sed 's/^define i128 @__multi3(i128 %a, i128 %b) {/define i128 @__multi3(i128 %a, i128 %b) alwaysinline {/' \
		$< > $(BLD)/multi3-inline.ll
	$(LLVM_AS) $(BLD)/multi3-inline.ll -o $@
	@rm -f $(BLD)/multi3-inline.ll

# Keep-list: the Rust test entry points plus libarena's control programs
# (the loader runs arena_buddy_reset) and the license. Everything else is
# internalized so globaldce can drop unreachable code — including the
# i128-returning __multi3 helper, which the BPF backend cannot compile
# unless it is actually referenced.
# libarena's C functions stay global: they carry __arg_arena BTF decl tags
# and are designed to verify standalone (inlining buddy_init's loops into
# the entry program blows the verifier's jump-complexity budget). Only the
# Rust side must be inlined (see scripts/force_inline.py).
$(BLD)/arena_syms.txt: $(ARENA_BCS)
	$(LLVM)/llvm-nm --defined-only $(ARENA_BCS) | \
		awk '$$2 ~ /[TtWw]/ {print $$3}' | sort -u | \
		grep -vE '^(bpf_arena_mem(cpy|cmp|set)|memset)$$' > $@

$(BLD)/%.keep: progs/%.rs $(BLD)/arena_syms.txt
	@mkdir -p $(BLD)
	grep -oE 'fn test_[a-z0-9_]+' $< | sed 's/^fn //' | sort -u > $@
	printf '%s\n' arena_get_info arena_alloc_reserve arena_buddy_reset _license arena >> $@
	cat $(BLD)/arena_syms.txt >> $@

# Two-stage opt: (1) internalize + dce, (2) force-inline every non-entry
# function (arena pointers must never cross a live call boundary — see
# scripts/force_inline.py) and optimize.
$(BLD)/%-opt.bc: $(BLD)/%-linked.bc $(BLD)/%.keep
	$(LLVM_DIS) $< -o $@.stage0.ll
	python3 scripts/lower_mem.py $@.stage0.ll $@.stage0.ll
	$(OPT) $$(sed 's/^/--internalize-public-api-list=/' $(BLD)/$*.keep | tr '\n' ' ') \
		--force-remove-attribute=cold \
		-passes='forceattrs,internalize,globaldce' $@.stage0.ll -o $@.stage1
	@rm -f $@.stage0.ll
	$(LLVM_DIS) $@.stage1 -o $@.stage1.ll
	$(OPT) $$(python3 scripts/force_inline.py $@.stage1.ll $@.stage2.ll $(BLD)/$*.keep) \
		-passes='forceattrs,always-inline,globaldce,default<O2>' $@.stage2.ll -o $@
	@rm -f $@.stage1 $@.stage1.ll $@.stage2.ll

# --- invoke->call, unreachable->ret (no Rust-side ksyms here) ---
$(BLD)/%-ksyms.bc: $(BLD)/%-opt.bc
	$(LLVM_DIS) $< -o $@.ll
	KSYM_BTF_FILES="$(KERNEL)/vmlinux" BPFTOOL="$(BTOOLDIR)/bpftool" TRAP_TO_BPF_THROW=0xC0DED \
		python3 $(RUSTBPF)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@
	@rm -f $@.ll

$(BLD)/%.bpf.o: $(BLD)/%-ksyms.bc
	$(LLC) -march=bpfel -mcpu=v4 -filetype=obj -o $@.tmp $<
	$(LLVM_OBJCOPY) \
		--remove-section=.eh_frame --remove-section=.rel.eh_frame \
		--remove-section=.gcc_except_table \
		--strip-symbol=rust_eh_personality $@.tmp $@
	@rm -f $@.tmp
	python3 ../scripts/btf_rename.py $@

# --- userspace runner (links against the harness libbpf) ---
$(BLD)/loader: loader.c
	$(CC) -O2 -o $@ $< \
		-I$(BTOOLDIR)/libbpf/include -I$(HEIM)/uml-harness/.build/bpf-next/tools/lib \
		$(BTOOLDIR)/libbpf/libbpf.a -lelf -lz

# --- run all tests inside the qemu guest ---
VNG ?= $(HOME)/.local/share/vng-venv/bin/vng
test: all
	PATH="$(dir $(VNG)):$$PATH" $(VNG) --run $(KERNEL)/arch/x86/boot/bzImage \
		--cpus 2 --memory 2G --rw -- \
		'cd $(CURDIR) && for o in $(BLD)/*.bpf.o; do ./$(BLD)/loader $$o || exit 1; done'

clean:
	rm -rf $(BLD)

.PHONY: all test clean
