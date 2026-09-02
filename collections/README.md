# Real Rust collections in BPF (arena-backed)

`alloc::{Box, Vec, String, VecDeque}` — the real ones, from the Rust
standard library — running inside SEC("syscall") BPF programs, backed by a
BPF arena through [libbpf/libarena]'s buddy allocator. Including the nested
ones: `Vec<Vec<u64>>` and `Box<Box<u64>>` chase a pointer that was stored
inside the arena, which v1 could not do.

```
$ make test          # boots the pinned qemu kernel via vng
OK   test_rs_box_in_box
OK   test_rs_vec_of_vec
bld/collections_nested.bpf.o: 2/2 passed
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
bpf-next carries libarena in-tree too, and the Makefile falls back to
`$(KERNEL_SRC)/tools/testing/selftests/bpf/libarena` when the submodule has
not been checked out.

## Architecture

- **libarena (C, clang)** provides the allocator: `arena_malloc`/
  `arena_free` over a buddy allocator with arena spinlocks, plus the arena
  map definition and the `arena_buddy_reset` init program (the loader runs
  it before the tests). Both take/return `void __arena *`, which Rust
  cannot spell, so glue/arena_glue.bpf.c wraps them as `arena_malloc_u64`/
  `arena_free_u64`.
- **arena-alloc (Rust)** is a `GlobalAlloc` over that: `alloc()` calls
  `arena_malloc_u64` and applies one hand-encoded `addr_space_cast` (the
  same byte-exact inline-asm idiom as progs/arena_atomics.rs); `dealloc`
  casts back and frees. Buddy blocks are power-of-two sized and aligned, so
  allocating max(size, align) meets any Layout.
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
   (scripts/force_inline.py) — for verifier budget, not for pointer
   typing; see "What force-inlining is actually for" below. rustc marks
   cold call *sites* (RawVec::grow_one) noinline, which must be stripped
   too. `FORCE_INLINE=0` turns it off, which is how the measurement below
   was taken.
4. **libarena's C functions stay global** (they are all in the keep list,
   so force_inline.py leaves them alone). Inlining them is not merely
   unnecessary, it does not work: force-inlining buddy_init and friends
   into `arena_buddy_reset` gives "the sequence of 8193 jumps is too
   complex" at 486779 insns, peak_states 29734 — the same
   pending-branch limit BTreeMap hits.

   What lets an arena pointer cross that boundary is **not** a BTF decl
   tag. The libarena this builds against carries no `__arg_arena`
   anywhere, and the object has zero DECL_TAGs; earlier versions of this
   file claimed otherwise. It works because the ABI is the arena's
   user-form address, which crosses as a plain scalar and is re-typed
   independently on each side — Rust with `arena_alloc::cast_kern`, C by
   clang inserting a cast at every `__arena` dereference:

       1: (85) call pc+41
          Func#1 ('arena_malloc') is global and assumed valid.
       2: R0=scalar()                          <- crosses as a scalar
       3: (bf) r0 = addr_space_cast(r0, 0, 1)  <- Rust re-casts

   That is what glue/arena_glue.bpf.c is for: `arena_malloc_u64` /
   `arena_free_u64` instead of the `void __arena *` originals.

   An `arg:arena` tag would only be needed to give a *Rust* global
   subprogram a real PTR_TO_ARENA parameter, and it would not be
   sufficient on its own — `verifier.c:18508` still hands the callee a
   SCALAR for an `ARG_PTR_TO_ARENA` argument, so the callee must
   `cast_kern` it anyway. The tag relaxes the caller-side contract only.
   (scripts/btf_rename.py does know never to sanitize DECL_TAG names,
   since "arg:arena" needs its colon; nothing here exercises it.)
5. **mem intrinsics lowered before inlining** (scripts/lower_mem.py):
   llvm.memcpy/memmove/memset and memcmp/bcmp become calls to byte-loop
   helpers in glue/arena_glue.bpf.c, and get inlined per call site —
   the verifier refuses one shared instruction reached with different
   pointer types (arena at one site, stack or rodata at another). The
   backward (memmove) walk needs the barrier_var idiom to stay in
   verifier-provable index form.
6. **The 64x64 widening multiply expanded** (scripts/lower_i128.py):
   alloc's checked layout arithmetic emits
   `llvm.umul.with.overflow.i64`, and BPF has no 64x64->128 instruction,
   so ISel legalizes it into a `__multi3` libcall that the backend then
   refuses ("A call to built-in function '__multi3' is not supported").
   The pass expands it to i64 arithmetic in the IR. The tree also links an
   `alwaysinline` `multi3.ll`, which is *not* what saves this: there is no
   call for the inliner to act on. With force-inlining the multiply
   constant-folds against a known element size and the problem is hidden,
   which is why it only surfaced when the helpers were left outlined.
7. **Re-casting pointers reloaded from the arena**
   (scripts/arena_recast.py) — this is what lifts the v1 pointer-chasing
   limit; see below.

## Pointer chasing, and why no backend work was needed

v1 recorded that `Vec<Vec<..>>` and `BTreeMap` could not verify, and that
fixing it meant "teaching the rustc BPF target an arena address space, or
an LLVM pass that re-inserts casts after pointer-typed loads". The first
half was right about the shape of the fix and wrong about its cost: a
*module-level IR pass* is enough, and neither rustc nor the LLVM BPF
backend needs to change.

The reason is what a `PTR_TO_ARENA` register actually holds. It is not a
kernel address. `kernel/bpf/fixups.c:1577` rewrites `addr_space_cast(rX,
0, 1)` — "convert to 32-bit mov that clears upper 32-bit" — so the register
carries the 32-bit arena offset and nothing else; the kernel base is added
by the access, via `BPF_PROBE_MEM32`. Applying that cast twice is therefore
two 32-bit movs: re-casting a value that already came out of the arena
**does not change the value**, it only restores the verifier typing that
the reload dropped. The fix is one no-op instruction per reloaded pointer:

```
23: (79) r2 = *(u64 *)(r2 +0)   ; R2=scalar()      <- v1: rejected here
24: (79) r7 = *(u64 *)(r2 +0)   ; R2 invalid mem access 'scalar'

23: (79) r2 = *(u64 *)(r2 +0)   ; R2=scalar()
24: (bf) r2 = addr_space_cast(r2, 0, 1)  ; R2=arena  <- inserted
25: (79) r7 = *(u64 *)(r2 +0)   ; accepted
```

`scripts/arena_recast.py` inserts them. It runs after the O2 stage, traces
arena provenance forward from the `cast_kern` that `arena_alloc::alloc()`
performs on each fresh allocation — through getelementptr / bitcast /
inttoptr / phi / select, through unpromoted stack slots, and through the
recast loads themselves — and casts every pointer load whose address is
*provably* arena-derived. Cycles resolve as a unit, which matters because
a tree or list descent is a cycle running through the load it is trying to
type (phi -> getelementptr -> load -> phi).

Two things to know about it:

- Nothing else is touched. `collections_smoke.bpf.o` gets 0 recasts;
  `collections_nested.bpf.o` gets 11. Flat collections are unaffected.
- A *non*-arena pointer (a `&'static str`, a stack address) stored into
  arena memory and read back is indistinguishable from an arena one here,
  and would be recast into a wrong-but-in-bounds arena offset. Today such a
  program is rejected outright; with the pass it would read garbage.
  Collections that store only allocator-produced pointers are unaffected.

### Can the pass be dropped?

Not for the real `alloc` containers, and the reason is not effort. The
analysis exists only because the address space is absent from the *type*:
`RawVec` holds `*mut T`, which rustc emits in address space 0 and always
will. Give the type an address space and the pass is unnecessary —
LLVM's `insertASpaceCasts` is operand-driven and wraps any load or store
whose pointer operand is in a non-zero address space, so no backend work
would be needed there either.

rust-bpf's `ArenaPtr<T>` does exactly that and needs no pass at all. It is
also not a way out here: it is an accessor API with no `Deref` and no
`&mut T`, deliberately, because handing out a Rust reference would hand
out an address-space-0 pointer and discard the thing the type exists to
carry. That rules out `alloc::` containers regardless of the `GlobalAlloc`
— `ArenaVec` exists precisely because `Vec` cannot be made to work that
way. So the choice is this pass plus the real `alloc` collections, or no
pass and `ArenaVec`-style substitutes.

## What force-inlining is actually for

v1 recorded that force-inlining was needed because arena pointers "keep
their PTR_TO_ARENA typing only inside the function that performed the
cast". That is true of *global* subprograms, whose arguments the verifier
gives `mark_reg_unknown` (verifier.c, `ARG_PTR_TO_ARENA`), but not of the
static ones the Rust helpers become here. Building with `FORCE_INLINE=0`
shows the typing surviving several frames deep:

    to caller at 868:
     frame4: ... fp-40=arena fp-48=scalar(id=51918,umin=1) fp-56=arena
    872: (79) r4 = *(u64 *)(r10 -56)  ; frame4: R4=arena
    873: (79) r8 = *(u64 *)(r4 +0)    ; frame4: R4=arena R8=scalar()

So arena_recast.py needs no cross-function extension, and outlining is a
correctness non-issue. What it costs is budget: a static subprogram is
re-verified at every call site, and `test_rs_grow_shrink` outlined runs to
`processed 1000001 insns (limit 1000000)`, peak_states 82321, against a
whole object that loads when inlined. Force-inlining stays.

The budget win that outlining *can* buy — a global subprogram is verified
once — is not reachable from Rust here. It requires the callee to
re-cast its own pointer arguments, and a Rust helper's parameters are a
mix: `RawVec::grow_one` takes `&mut self`, a stack pointer, alongside the
arena pointer inside it. There is no sound blanket cast at entry.

## Known limits

- **`BTreeMap` still does not load — but no longer for the v1 reason.**
  With arena_recast.py its child links type correctly (the verifier log
  shows `addr_space_cast` before each descent and accepts the derefs).
  What stops it is `env->stack_size > BPF_COMPLEXITY_LIMIT_JMP_SEQ`
  (verifier.c:1751, limit 8192) — the queue of *pending unexplored
  branches*, not the instruction count and not the state count: three
  inserts give "the sequence of 8193 jumps is too complex" at 94237 of
  1000000 insns with total_states 1038. Outlining does not help
  (`FORCE_INLINE=0`: 135029 insns, same wall). Nothing on this side of the
  toolchain reaches it — it is the shape of liballoc's search and split
  code against a verifier limit.
- Verifier budgets bound working-set sizes (the sort test uses 24
  elements; `Vec::dedup` on symbolic lengths exceeds 1M insns).
- Kernel-side only: sharing collection layouts with userspace would need
  cast_user discipline on every stored pointer.

## Layout

    vendor/libarena/   git submodule (pinned)
    glue/              u64-ABI shims + inlined mem helpers (C)
    arena-alloc/       the GlobalAlloc (Rust)
    progs/             test programs (Rust)
    scripts/           force_inline.py, lower_mem.py, lower_i128.py,
                       arena_recast.py
    loader.c           opens the object, runs arena_buddy_reset, then
                       bpf_prog_test_run()s every test_* program
    Makefile           the full pipeline; `make test` runs in qemu
