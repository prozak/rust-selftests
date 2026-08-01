# Canonicality audit of the Rust translations

*2026-08-01. Scope: the 10 verified translations in `progs/` plus the
harness-blocked `stacktrace_map.rs`, audited against `TRANSLATING.md` (the
current canon) and against what idiomatic, safety-reviewable Rust for this
pipeline ought to look like. Constraint unchanged: no aya, no bpf crate —
upstream rustc/LLVM straight to BPF, C-object-equivalent BTF/ABI, kernel
test harness as oracle.*

## 1. Summary

The corpus is **ABI-canonical but not Rust-canonical**. Every translation
is a faithful drop-in for its clang-built object (the oracle enforces
this), and the idioms are consistent enough that agents reproduce them
reliably (20/20 first-attempt passes in the model bench). But measured as
Rust:

- **76 `unsafe` sites in 1,321 lines** (~1 per 17 lines), none of them
  encapsulated — every kernel interaction is open-coded unsafety at the
  call site.
- **24 `transmute(ID)` helper-call thunks** duplicated across files —
  `bpf_get_current_pid_tgid` is redefined in 5 files, `bpf_map_update_elem`
  in 4, `bpf_map_lookup_elem` in 3 — with signature drift already visible
  (early files monomorphize the map type per map; `stacktrace_map.rs`
  introduced the generic `<M, K, V>` form, which is the better one).
- **25 `static mut` globals** accessed through a mix of direct
  `unsafe { g = .. }` assignment and `addr_of_mut!` — inconsistent, and
  `static mut` references are denied in edition 2024, so the current form
  has a hard expiry date.
- **14 map definitions** each hand-rolling the BTF-encoding struct +
  `unsafe impl Sync` + null-initialized instance (~15 lines of boilerplate
  per map).
- Per-file macros (`test_field!`, `cb_step!`, `bump!`, `check!`) reinvent
  volatile field access; the crate skeleton (license, panic handler) is
  repeated verbatim 11 times.

None of this is a correctness problem today — the oracle guarantees the
objects behave. It is a *scalability and reviewability* problem: a sweep
generating hundreds of translations in this style multiplies unencapsulated
unsafe code, and a safety policy (the planned deliverable) has nothing to
attach to when every file is its own free-standing unsafe dialect.

**Recommendation in one line: extract a `bpf-rs-core` support crate (linked
like the existing `btf_macros` crate) that owns the five encapsulatable
idioms below, re-verify all 10 programs through the unchanged oracle after
each adoption step, and update TRANSLATING.md so future agent translations
generate against the crate instead of open-coding.**

## 2. Idiom-by-idiom assessment

| # | Idiom | Current form | ABI-forced? | Canonical gap |
|---|---|---|---|---|
| 1 | Crate skeleton | `#![no_std] #![no_main]`, license static, `loop{}` panic handler ×11 | partly (license bytes are ABI) | pure boilerplate → `bpf_license!("GPL")` macro + shared panic handler in crate |
| 2 | Program decl | `#[link_section] #[no_mangle] extern "C" fn` with raw-pointer ctx | section string + symbol name are ABI | attribute macro `#[bpf_prog("fentry/...")]` could type the ctx and hide the section string, but plain attributes are honest and greppable — LOW priority |
| 3 | fentry arg access | `arg(ctx, i)` + `as` truncation, helper redefined per file | ctx layout is kernel ABI | one crate fn (or a `FentryCtx` wrapper with `arg::<T>(i)`); C's `BPF_PROG` equivalent macro is the ceiling, not required |
| 4 | Globals | `static mut` + mixed direct-assign / `addr_of!` access | names/types/init are ABI (skeleton members) | **worst gap.** UB-adjacent under Rust aliasing rules (userspace writes them concurrently!), denied in edition 2024. Canonical: `Global<T>`/`UnsafeCell<T>` wrapper with volatile get/set — must verify wrapper stays BTF-invisible (skeleton must still see plain `u64`) |
| 5 | .rodata config | `#[link_section = ".rodata"]` + `read_volatile` | yes | fold into `Global` story as `RoData<T>` |
| 6 | Map defs | hand-rolled struct of `*const [i32; N]` members + `unsafe impl Sync` + null instance | the *BTF shape* is ABI (libbpf contract) | const-generic `Map<const TYPE: i32, K, V, const MAX: i32>` in the crate *if* generic instantiation reaches BTF with the right member shape — needs a spike; BTF struct *name* is not load-bearing for maps (unlike ctx structs), only the VAR name and member layout are. Fallback: `bpf_map!` declarative macro emitting today's exact struct |
| 7 | Helper calls | `transmute(HELPER_ID)` fn-pointer thunk per file | the *call insn* is ABI; the thunk is not | single `helpers` module in the crate, generic over map type like `stacktrace_map.rs` already does; IDs from one table (mirror of uapi FN list). Eliminates all 24 duplicated transmutes. This is the same trick C's `bpf_helpers.h` uses — the transmute itself is as canonical as this pipeline gets; the sin is the duplication |
| 8 | kfuncs | `extern "C"` decl + add_ksyms reloc | yes | already canonical; crate can host common decls |
| 9 | CO-RE | `#[btf]` proc macro from rust-bpf | yes | already crate-shaped; keep |
| 10 | Ctx field access (tc/skb) | per-file volatile macros over `addr_of!` | narrow/volatile loads are verifier-facing | `VolatileField`-style accessors in crate; kills `test_field!`/`cb_step!`/`bump!`/`check!` reinvention |
| 11 | Atomics | `AtomicIsize` view punned onto `static mut isize` (test_ringbuf) | skeleton must see `long`, not a struct — that's why the pun exists | document as sanctioned pattern in crate (`atomic_view::<T>()`), or spike whether `AtomicIsize`'s BTF can be int-shaped; the pun is aliasing-gray but LLVM-defined here |
| 12 | asm barriers | `#![feature(asm_experimental_arch)]` + self-move asm (`__sink` equivalent, test_global_func1) | line-info quirk forces the 1-insn form | crate `sink()` fn with the comment; nightly feature is a toolchain gap (below) |

## 3. Findings that are *not* crate-fixable (language/toolchain gaps)

1. **BTF_KIND_DECL_TAG cannot be emitted.** clang derives it from
   `__attribute__((btf_decl_tag))` via DI annotations rustc has no syntax
   for. Consequence today: negative verifier tests (`__failure`/`__msg`)
   are untranslatable as *negative* tests — `test_global_func1.rs` had to
   invert the semantics (shrink the stack buffers so the object loads).
   Any sweep will hit this for every `__failure` program; they should be
   classified "blocked: decl_tag", not attempted. Upstream fix: rustc
   attribute → DIAnnotation plumbing (LLVM BPF backend already consumes
   it).
2. **Rust DWARF int names poison BTF** (`u64` vs `unsigned long long`) —
   worked around post-hoc by `scripts/btf_rename.py`. Proper fix upstream
   in libbpf's btf_dump (canonicalize int names) or a rustc option.
   Already noted in project memory; unchanged.
3. **`llvm-objcopy --update-section` corruption claim** (stacktrace_map):
   agent-reported, **unverified** — `.rel.BTF` `sh_info` corruption at one
   exact BTF size, worked around with padding statics inside the
   translation. Even if real, the workaround belongs in `btf_rename.py`
   (rewrite sections without objcopy, e.g. via pyelftools), never in a
   translation. Action: reproduce minimally before trusting; the padding
   statics must not become a copied idiom.
4. **Nightly features**: pipeline already needs `RUSTC_BOOTSTRAP=1`
   (rust-src, LLVM bitcode flow); `asm_experimental_arch` for BPF inline
   asm adds to the list. Fine for the experiment; a bar to clear for any
   "canonical" claim upstream.
5. **UAPI ctx struct names are load-bearing** (`__sk_buff` etc., kernel
   matches BTF by name for freplace/global-func args) — forces
   `non_camel_case_types` forever. A crate can ship the canonical ctx
   structs once (with the full UAPI layout) instead of per-file prefixes,
   which also removes the "declare the needed prefix yourself" divergence
   (three files carry three different-length `__sk_buff` prefixes today).

## 4. Safety-policy view of the unsafe surface

Categorizing all 76 unsafe sites:

| category | sites | encapsulatable? |
|---|---|---|
| helper-call thunks (transmute + call) | 24 | yes — crate helpers module |
| `static mut` global access | ~25 | yes — `Global<T>` wrapper |
| ctx field access (volatile/deref) | ~15 | yes — ctx structs + accessors in crate |
| map-def `Sync` impls | 14 | yes — crate map type |
| probe-style raw derefs (fentry BTF ptrs, ringbuf sample writes) | ~8 | partially — wrappers can bound but not remove; this is the irreducible core |
| asm barriers | 2 | yes — crate `sink()` |

I.e. **~90% of today's unsafe surface is encapsulatable** into one
auditable crate; the residual is small enough that a per-program safety
argument ("only derefs verifier-typed pointers") becomes tractable — which
is exactly what the safety-policy deliverable needs, and what a future
Verus pass would want to reason about.

## 5. Proposed next steps (ordered)

1. **Spike: BTF shape of const-generic map defs** (idiom 6) — one map,
   `bpftool btf dump` diff against the C object. Decides `Map<...>` vs
   `bpf_map!`. Half a day.
2. **Build `bpf-rs-core`** with idioms 1, 3, 6, 7, 10 (skeleton macro,
   fentry args, maps, helpers, ctx accessors + canonical UAPI ctx structs).
   Link it the way `btf_macros` already links. Re-verify all 10 programs
   (`make verify` + full `make test-<name>` sweep) after each idiom lands —
   the oracle is the equivalence proof.
3. **Migrate the 10 translations** to the crate; measure the delta (expect
   ~40-50% line reduction and unsafe sites dropping to the irreducible
   ~10).
4. **Globals redesign** (idiom 4) last — it's the only one with real BTF
   risk (skeleton member types must stay primitive), and edition-2024
   pressure makes it worth doing carefully rather than first.
5. **Update TRANSLATING.md** to the crate idiom and re-run a 2-3 program
   agent bench (sonnet-5) to confirm the loop still first-attempts against
   the new canon.
6. File the upstream issues: rustc decl_tag attribute, libbpf btf_dump int
   names; minimally reproduce the llvm-objcopy claim before filing that
   one.
