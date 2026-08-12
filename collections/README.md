# Real Rust collections in BPF (arena-backed)

`alloc::{Box, Vec, String, VecDeque}` — the real ones, from the Rust
standard library — running inside SEC("syscall") BPF programs, backed by a
BPF arena through [libbpf/libarena]'s buddy allocator.

```
$ make test          # boots the pinned qemu kernel via vng
OK   test_rs_box
OK   test_rs_grow_shrink
OK   test_rs_sort
OK   test_rs_string
OK   test_rs_vec
OK   test_rs_vecdeque
bld/collections_smoke.bpf.o: 6/6 passed
```

[libbpf/libarena]: https://github.com/libbpf/libarena — vendored as a git
submodule under `vendor/libarena`, pinned so we control what we consume.

## Architecture

- **libarena (C, clang)** provides the allocator: `arena_malloc_internal`/
  `arena_free` over a buddy allocator with arena spinlocks, plus the arena
  map definition and the `arena_buddy_reset` init program (the loader runs
  it before the tests).
- **arena-alloc (Rust)** is a `GlobalAlloc` over that: `alloc()` calls
  `arena_malloc_internal` (u64-only ABI — Rust cannot express the __arena
  address space) and applies one hand-encoded `addr_space_cast` (the same
  byte-exact inline-asm idiom as progs/arena_atomics.rs), so collections
  only ever hold kernel-view pointers; `dealloc` casts back and frees.
  Buddy blocks are power-of-two sized and aligned, so allocating
  max(size, align) meets any Layout.
- **Everything merges at the LLVM bitcode level** — clang-built libarena,
  rustc-built program, prebuilt libcore/liballoc — into one object with
  one BTF. No BPF static linker involved.

## What it took (each of these is load-bearing)

1. **panic=immediate-abort libcore/liballoc** (built locally under
   bld/deps, separate from the translation pipeline's deps): collection
   internals carry panic paths whose formatting (core::fmt) the BPF
   backend cannot lower (6-arg calls, stack arguments). immediate-abort
   panics carry no fmt at all.
2. **llvm.trap -> bpf_throw**: immediate-abort lowers panics to llvm.trap
   = __bpf_trap, and the verifier rejects any *reachable* trap — and the
   allocation-failure path is always reachable. Rewriting traps to the
   bpf_throw kfunc (cookie 0xC0DED) turns a runtime panic/OOM into a clean
   program exit with a loudly-nonzero retval (add_ksyms.py,
   TRAP_TO_BPF_THROW).
3. **Force-inlining all Rust code into the entry programs**
   (scripts/force_inline.py): arena pointers keep their PTR_TO_ARENA
   verifier typing only inside the function that performed the cast;
   returned through a subprogram they degrade to scalars and the next
   deref is rejected. C re-casts at every boundary via the __arena address
   space — rustc has no equivalent, so no live call boundary may remain.
   rustc marks cold call *sites* (RawVec::grow_one) noinline, which must
   be stripped too.
4. **libarena's C functions stay global**: they carry `arg:arena` BTF decl
   tags and verify standalone; inlining buddy_init's loops into an entry
   would blow the verifier's jump budget. (scripts/btf_rename.py learned
   to never sanitize DECL_TAG names — "arg:arena" needs its colon.)
5. **mem intrinsics lowered before inlining** (scripts/lower_mem.py):
   llvm.memcpy/memmove/memset and memcmp/bcmp become calls to byte-loop
   helpers in glue/arena_glue.bpf.c, and get inlined per call site —
   the verifier refuses one shared instruction reached with different
   pointer types (arena at one site, stack or rodata at another). The
   backward (memmove) walk needs the barrier_var idiom to stay in
   verifier-provable index form.
6. **__multi3 force-inlined**: alloc's checked layout math calls it, and
   an out-of-line i128-ABI function cannot be compiled for BPF.

## Known limits (v1)

- **Pointer-chasing collections (BTreeMap, Vec<Vec<..>>) do not verify**:
  node/child pointers stored *inside arena memory* come back as scalars
  on reload; only a cast at every deref (clang's __arena address space)
  re-establishes typing, and rustc cannot express that. Fixing this
  properly means teaching the rustc BPF target an arena address space, or
  an LLVM pass that re-inserts casts after pointer-typed loads from arena.
- Verifier budgets bound working-set sizes (the sort test uses 24
  elements; `Vec::dedup` on symbolic lengths exceeds 1M insns).
- Kernel-side only: sharing collection layouts with userspace would need
  cast_user discipline on every stored pointer.

## Layout

    vendor/libarena/   git submodule (pinned)
    glue/              u64-ABI shims + inlined mem helpers (C)
    arena-alloc/       the GlobalAlloc (Rust)
    progs/             test programs (Rust)
    scripts/           force_inline.py, lower_mem.py
    loader.c           opens the object, runs arena_buddy_reset, then
                       bpf_prog_test_run()s every test_* program
    Makefile           the full pipeline; `make test` runs in qemu
