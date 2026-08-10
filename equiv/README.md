# Z3 semantic equivalence checker (Heimdall stages 4–5 analog)

Proves, per BPF program, that the Rust translation's object code is
observationally equivalent to the kernel's C-compiled object: for every input
(symbolic context, symbolic kernel memory, symbolic initial globals), both
produce the same return value and the same final contents of every named
global and of the context.

## Usage

```sh
# one program (venv: ../../z3-venv)
../z3-venv/bin/python equiv/check.py fentry_test

# whole corpus, 10-way parallel
equiv/sweep.sh <names-file> <out-dir> 10
```

`check.py` exits 0 iff every paired program is proved EQUIV (or EQUIV32).

## Files

- `bpfelf.py` — standalone ELF64-LE reader: sections, symbols, RELs, and
  `.BTF.ext` CO-RE relocation coverage (per-section).
- `bpfsym.py` — BPF ISA → Z3 lifter with path-enumerating symbolic execution.
  Anything unmodeled raises `Bail` (never guesses).
- `check.py` — pairs programs by (section, func) across the two objects,
  builds ITE path summaries, asks Z3 for a distinguishing input.
- `sweep.sh` — parallel driver + verdict histogram.

## Model

- Registers hold 64-bit bitvectors or `Ptr(region, offset)` values.
- Regions: shared symbolic `ctx`; shared symbolic `kmem` (backs probe-reads
  through scalar pointers, read-only); one shared symbolic array per named
  writable global (`g:<sym>` — the observables); per-object concrete-initialized
  read-only sections; per-run 512-byte stack; opaque `map:<name>` pointers.
- Paths are enumerated with Z3 feasibility pruning; per-path summaries are
  ITE-folded, so the final query covers all executions at once.
- Void-return programs (r0 never assigned — verifier-enforced BTF void) skip
  the return-value comparison.
- `EQUIV32`: return values agree in the low 32 bits only; benign when the BTF
  return type is ≤32 bits (not yet checked automatically).
- `CORESKIP`: section carries unapplied CO-RE relocations; comparing pre-load
  bytecode is not meaningful. Needs load-time reloc application (v2).

Helper calls (tier 1):

- probe_read/_kernel/_user: byte copy from the shared `kmem` (or source
  region) — deterministic, no oracle; concrete size ≤ 512 required.
- probe_read_*_str: NUL position abstracted as a shared per-call-index oracle
  length clamped to [1, size]; bytes past it keep prior contents.
- Argument-free environment reads (ktime, pid_tgid, smp_processor_id, ...):
  shared oracle streams at the helper's true return width; pid_tgid is
  additionally masked to kernel-possible values (both halves < 2^31), since
  C sign-extends `int` pid compares where Rust compares 32-bit.

Helper calls (tier 2) — observable call trace:

- Side-effecting helpers (map_update/delete/push/pop/peek,
  perf_event_output, ringbuf_output, get_stackid, trace_printk) append an
  event `[helper id][len][payload]` to a shared `trace` region that is
  compared like any other observable: equivalence requires the same call
  sequence with the same arguments. Key/value pointer args are compared by
  pointed-to bytes, sizes taken from each object's own `.maps` BTF def (so a
  key/value-size mismatch between C and Rust surfaces as INEQUIV). The
  concrete trace cursor makes encodings prefix-comparable: the first
  diverging event differs in place, and a missing trailing event leaves
  symbolic `trace_init` residue some input distinguishes.
- Their environment-determined errno return is a shared per-call-index
  oracle sign-extended from 32 bits (real returns fit in an int; full-width
  freedom would fake divergences between C `long` and Rust `i32` compares).
  Per-index sharing is sound *because* traces are compared: equal traces
  imply equal map/env state at the nth call.
- map_pop/peek produce value bytes from a shared per-call-index oracle,
  written only when the shared errno says success.
- trace_printk requires a concrete format string (rodata/stack); numeric
  conversions compare at the width the kernel reads (%d → 4 bytes,
  %ld/%lld → 8); `%s`/`%p` bail.
- Pure environment reads keyed by their question, not by call order:
  get_current_comm bytes are `oracle(size, k)` (kernel NUL-pads per size, so
  different sizes must not alias); skb_load_bytes reads a shared symbolic
  `skbdata` packet array with success `oracle(offset, len)`; both zero-fill
  the destination on error, as the kernel does.
- bswap (BPF_END) and atomics (add/or/and/xor ± fetch, xchg, cmpxchg,
  load-acquire/store-release) are modeled exactly; atomics get sequential
  semantics, consistent with the model's single-threaded stance.
- Still bailing → tier 3: map_lookup_elem / ringbuf_reserve (pointer
  returns); tier 4: subprog calls, packet/ctx-pointer stores, pointer
  compares across regions, spilled pointer stores.

Rust v0-mangled static names are normalized to their source identifier so the
same logical global maps to the same region in both objects. The C object's
BTF is ground truth for return contracts: void functions skip the return
comparison, ≤32-bit return types compare low 32 bits.

`equiv/waivers.tsv` records accepted semantic divergences (verdict WAIVED,
non-failing, reason required). Entries: test_stack_var_off — the C program
deliberately reads uninitialized stack residue; the Rust translation
zero-initializes, a deterministic refinement. bpf_flow/flow_dissector_4 —
LLVM compiles the C source's `!(data + thoff)` to `!data` via pointer
provenance; divergence needs a NULL skb->data, kernel-impossible.

Soundness stance: unsupported constructs BAIL rather than being approximated,
so EQUIV verdicts only rest on modeled semantics. Known deliberate
assumptions: probe-reads never fault; LD_IMM64 global/map pointers are
non-NULL; both programs see the same kernel memory snapshot and the same
initial (uninit) stack residue; the nth call to a given helper observes the
same environment value in both programs.

## Verdict sweeps (2026-08-05)

550-object corpus, per-program totals:

- v1 (no helpers): 335 EQUIV / 0 INEQUIV; all 26 initial INEQUIVs were
  model artifacts (void rets, .text subprogs, .struct_ops data, CO-RE).
- tier 1 (probe_read family + pure oracles): **366 EQUIV / 0 INEQUIV /
  1 WAIVED** (83 objects fully proved). The tier-1 triage surfaced and fixed:
  oracle return widths, pid_tgid range refinement, Rust static demangling,
  BTF-based return contracts, shared stack residue — and found one genuine
  divergence (test_stack_var_off, waived).
- tier 2 (2026-08-10; call trace + bswap + atomics + retval state):
  **456 EQUIV / 0 INEQUIV / 2 WAIVED** (106 objects fully proved; object
  verdicts 106 EQUIV / 268 BAIL / 164 CORESKIP / 11 NOPROGS / 1 TIMEOUT).
  Negative controls: mutated map_update flags and key offset both flagged
  INEQUIV through the trace observable. **Second true finding**:
  cgroup_getset_retval_getsockopt compared `optlen > page_size` signed where
  C (with `__u32 page_size`, unlike its sibling files' `__s32`) compares
  unsigned — the Rust translation misbehaved for negative optlen, invisible
  to the test oracle; fixed in progs/ and re-proved + QEMU-verified.

Results tables: `results/`. Remaining bail histogram (call sites):
subprog calls ×346, map_lookup ×96, tail_call ×21, .text (subprog address)
relocs ×18, spilled pointer stores ×16, packet/ctx-pointer stores ×15, then
a long tail of context-specific helpers (get_attach_cookie, check_mtu,
get_local_storage, sk_lookup_tcp, redirect_map, ...).

## Roadmap

1. **Tier 3**: map_lookup_elem returned-pointer model (per-index mapval
   regions + shared NULL oracle) — 96 call sites, and 21 objects wait on
   it alone.
2. **Tier 4**: subprog inlining (346 bail sites), spilled pointer stores,
   packet pointers (skb->data/data_end as a region), pointer compares
   across regions (shared symbolic region bases).
3. **CO-RE application**: apply `.BTF.ext` relocations against the pinned
   vmlinux BTF (like libbpf) before lifting, unlocking the CORESKIP class
   (504 programs).
4. **Regression guard**: bytecode-hash fast path; re-prove after
   quality-layer edits, alarm on equivalence break.
