# verifier_* sweep (2026-10-17)

Issues #25 and #27: the `verifier_*.c` selftests, 143 files of 1899
programs, most of them (1688) hand-written BPF asm in `__attribute__((naked))`
functions and the rest (211) C bodies. At the end 140 files are translated;
the nightly `nightly/20261017-verifier-sweep` gates all 140 PASS and proves
1675 of their 2101 programs. The corpus went from 638 to 776 objects.
Session: `https://claude.ai/code/session_017nM4esxgEYEYcy9Gia2mTD`, commits
032ed7e..88992f1 on top of the LLVM 23 move (6a3f216).

## The naked programs: generated, not translated

A naked program is already BPF: the only translation is to carry the asm
text into a `BPF_NAKED` Rust function with the same section, name, operands
and BTF. `scripts/naked_gen.py <name>` does that from two inputs:

- the C source, preprocessed with the selftests' own clang flags, for the
  asm text and the `__attribute__((naked))` functions; every `"i"` operand is
  resolved by compiling a probe (`#include` the C, one `.8byte %[op]` per
  operand) and reading the values and relocations back, so a helper becomes
  `call 1`, a map or subprogram or kfunc becomes a `sym`, constants and
  instruction encodings become decimal; `%=` is numbered like AsmPrinter's
  `${:uid}`; `"r"` operands become `in(reg) addr_of!` with the C's clobbers
  so the chosen register matches clang's;
- the C object's BTF and ELF for everything else: maps, globals, kfunc
  externs, license, `test_tags!` (the `bpf_misc.h` annotations, as decl
  tags), `arg_tags!`, `btf_type_tags!` (kptr and arena tags, including
  `fn.<index>` / `fn.ret` entries for subprogram prototypes), `.struct_ops`
  and `.addr_space.N` DATASECs, hidden symbols (`.hidden` directives),
  initialized prog-array slots, and `// BPF_PROGRAM_ORDER:` for the C's
  source order.

`scripts/naked_verbatim.py`, run by translint as the `naked-verbatim`
class, compares every `// BPF_NAKED:` function's instruction stream with the
C object's: same section, same bytes, and where libbpf patches an immediate
(a map, a subprogram, a kfunc) the same relocation symbol. It is an ERROR,
so a generated file that drifts from the C fails `make all`.

Survey first: 79 files were pure naked and generated outright (pilot of 5,
then 74). They gated 77/77 PASS on the first try (two had no consumer);
the generator's bugs all showed up as `naked-verbatim` diffs before any gate.

## The C bodies: hand files beside the generated ones

A mixed file keeps its generated part in `progs/<name>.rs` and the hand
part in `progs/hand/<name>.rs`, `include!`d from the main file;
`naked_gen.py --with-c-bodies` writes the hand file once, with the C text
and `todo!()` stubs, and never overwrites it. The hand file steers the
generator with comment directives: `GEN_SKIP_TYPE` (a C type defined by
hand; types only reachable through it are pruned too), `GEN_TAGS` (a
per-program `test_tags!` override, needed where the C object is built for
`-mcpu=v3` and the Rust for v4 and instruction counts differ), and carried
markers (`BTF_TYPE_ID`, `BTF_KSYM`, `BTF_C_CHAR`, `BTF_C_VOID`,
`RUSTC_OPT_LEVEL`, `BPF_NAKED`, `translint: allow(<class>:<program>)`).
Fifty-six hand files were written this way; `verifier_ctx` (117 bodies)
through a pattern script, the arena family by hand with the `cast_kern`,
`arena_base()` and `can_loop()` idioms.

What the hand translations taught (each cost a gate or guard failure):

- The verifier's own frame layout matters to the C's expectations: an
  aligned u32 key is one u32 store at the C's slot, and rustc puts the last
  local at fp-8 where clang puts the first. Dynptr locals must be
  uninitialized and at the C's frame offset (the prover keys kfunc
  out-pointers by address).
- A `char name[] = "..."` initializer becomes `llvm.memcpy`, which
  `add_ksyms.py` turns into a `bpf_arena_memcpy` kfunc call this kernel
  lacks: write the bytes as explicit stores.
- LLVM's dead-argument elimination passes poison for an unused parameter
  of an external function up the call chain (clang keeps `w1 = 0`); the
  verifier then sees a context where it expected a scalar. Keep the
  parameter alive with `bpf_rs_core::helpers::sink_val`.
- A `__sink` must be a real instruction (`asm!("{0} = {0}", inout(reg))`):
  an empty asm leaves two line infos at one offset and the kernel rejects
  the object with EINVAL.
- struct_ops programs want a C `void *` context: Rust's `*mut c_void` is a
  pointer to an enum in BTF, which `btf_validate_prog_ctx_type` refuses.
  The generator emits `// BTF_C_VOID: c_void` when an `extern "C"`
  signature or struct field holds one.
- A C `__hidden` global shared by several programs must stay hidden in the
  Rust object too (`core::arch::global_asm!(".hidden name")`), otherwise
  libbpf tries to mmap the `.bss.X` map holding a spin lock and fails with
  ENOTSUPP.
- A `#[btf]` CO-RE view is a unit struct: a local named like it shadows the
  type.
- rustc's BPF C ABI passes aggregates (structs, u128) indirectly and
  returns them through sret; clang flattens them into registers. The
  `verifier_aggregate_arg` and `verifier_aggregate_ret` C bodies therefore
  cannot be plain Rust, and `verifier_bitfield_write` cannot be translated
  because a CO-RE bitfield relocation needs bitfield members in the
  object's own BTF, which Rust cannot define. These three files are left
  out.
- Touching `equiv/*.py` changes the prover's tool hash and the guard
  demands a full re-sweep; the generator parses ELF `st_other` itself
  instead of extending `equiv/bpfelf.py`. Likewise a gate against a
  half-built object (the BTF scripts not yet run) reports a bogus
  `unexpected_load_failure`, and generating `todo!()` stubs for a file and
  then gating before translating them fails the gate's `make all`.

## The nightly

Stages: ci-fast 3 s, rebuild 216 s, translint 19 s, proof 1559 s (eight
jobs), QEMU gate 2662 s (eight workers), codegen 3 s.

| gate | objects |
|---|---:|
| PASS | 766 |
| FAIL | 0 |
| NO-ORACLE | 10 |

| proof | objects |
|---|---:|
| EQUIV | 505 |
| BAIL | 191 |
| TIMEOUT | 49 |
| UNKNOWN | 16 |
| NOPROGS | 13 |
| INEQUIV | 1 (`cpumask_success`, #36, as before) |
| ERROR | 1 (`verifier_arena_scalar`) |

No verdict of the 638 objects of the LLVM 23 run changed. Among the 140
verifier objects: 60 EQUIV, 69 BAIL (partial proofs: expected-rejection
programs, unmodeled helpers and kfuncs, `r11` stack arguments), 10 TIMEOUT
(`arena_large`, `bits_iter`, `bounds`, `global_subprogs`, `idoms`,
`iterating_callbacks`, `linked_scalars`, `loop_hierarchy`, `movsx`,
`scev`), and the ERROR, a Z3 type error in `equiv/bpfsym.py`'s `_atomic`
("Third argument must be a Z3 bit-vector expression"), a checker defect
to fix in a session that can afford the full re-sweep its tool-hash change
triggers. The nightly's own status is FAIL only because the proof stage
exits 1 on the known INEQUIV and the ERROR.
