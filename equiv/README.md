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

Helper calls (tier 3) — nullable pointer returns:

- map_lookup_elem (and _percpu_elem, sk/inode/task/cgrp storage_get) emits
  a trace event with its question (map, key bytes / object+flags), then
  FORKS the path on a shared per-call-index NULL oracle: in any one model
  both programs' nth call takes the same branch. The non-null side returns
  a pointer into a per-call-index `mapval:` region with shared initial
  contents; writes through it are map state, compared as observables.
  Sharing per index is justified exactly as in tier 2: the trace pins the
  question and the mutation order. get_local_storage is verifier-typed
  non-null, so it gets the region without the fork.
- Same-key aliasing between separate lookups is NOT modeled (each call gets
  a fresh region); this cannot fake equivalence — a value written via one
  pointer and reread via another shows up as a mapval observable diff — and
  adds no false INEQUIVs beyond what trace equality already demands.
- map-in-map lookups return a dynamic inner-map handle whose key/value
  sizes come from the outer def's `values` BTF member.
- ringbuf_reserve forks NULL/pointer into a shared-residue `rbuf:` region;
  submit's trace event captures the buffer bytes — publication is the
  observable moment — while discarded buffers stay unobservable, as in the
  kernel. ringbuf_query is a per-index oracle read with a trace event.
- spin_lock/unlock are no-ops under sequential semantics, kept as trace
  events (region + offset) so lock placement must match.
- Pointer spills to the stack live in a per-region shadow keyed by concrete
  offset: 8-byte reloads return the pointer, partial/overlapping reads bail
  rather than see garbage, and data overwrites invalidate the slot.
- Still bailing → tier 4: subprog calls, packet/ctx-pointer stores
  (skb data/optval windows), pointer compares across regions (needs shared
  symbolic region bases), kptr_xchg, tail_call.

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

- tier 3 (2026-08-10; nullable-pointer helpers + pointer spills +
  map-in-map): **495 EQUIV / 0 INEQUIV / 2 WAIVED / 4 UNKNOWN** (128
  objects fully proved; object verdicts 128 EQUIV / 237 BAIL /
  164 CORESKIP / 11 NOPROGS / 9 TIMEOUT / 1 UNKNOWN). Negative controls:
  mutated lookup key, value flowing through the looked-up pointer, and a
  store offset through it — all flagged INEQUIV (the last via the mapval
  region observable). The 9 TIMEOUTs are the pyperf/strobemeta
  verifier-stress class: single-side path enumeration alone exceeds 300 s
  (50+-iteration unrolled loops; would need join-point path merging).
  access_map_in_map is UNKNOWN — Z3 gives up on its equality query even at
  a 5-minute budget. strobemeta_nounroll1 bails on a symbolic-size
  probe_read (bounded symbolic copies are future work).

Results tables: `results/`.

## Roadmap

1. **Tier 4**: subprog inlining (346 bail sites), packet/ctx-pointer
   window stores (skb->data/optval; needs pointer-field regions), pointer
   compares across regions / pointer-as-data (needs shared symbolic region
   bases), kfunc calls, tail_call, symbolic-size copies.
2. **CO-RE application**: apply `.BTF.ext` relocations against the pinned
   vmlinux BTF (like libbpf) before lifting, unlocking the CORESKIP class
   (504 programs).
3. **Path-merging at join points** for the pyperf/strobemeta TIMEOUT class.
4. **Regression guard**: bytecode-hash fast path; re-prove after
   quality-layer edits, alarm on equivalence break.
