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
- Everything else (maps, printk, kfuncs, subprogs) still bails → tiers 2–4.

Rust v0-mangled static names are normalized to their source identifier so the
same logical global maps to the same region in both objects. The C object's
BTF is ground truth for return contracts: void functions skip the return
comparison, ≤32-bit return types compare low 32 bits.

`equiv/waivers.tsv` records accepted semantic divergences (verdict WAIVED,
non-failing, reason required). First entry: test_stack_var_off — the C
program deliberately reads uninitialized stack residue; the Rust translation
zero-initializes, a deterministic refinement.

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

Results tables: `results/`.

## Roadmap

1. **Tier 2**: observable call-trace framework for side-effecting helpers
   (map_update etc.) — sequence equality of (helper, args), pointer args
   compared by pointed-to bytes using key/value sizes from map BTF defs.
2. **Tier 3**: map_lookup_elem returned-pointer model (per-index mapval
   regions + shared NULL oracle).
3. **Tier 4**: subprog inlining (345 bail sites), atomics, bswap, pointer
   spills to stack.
4. **CO-RE application**: apply `.BTF.ext` relocations against the pinned
   vmlinux BTF (like libbpf) before lifting, unlocking the CORESKIP class
   (504 programs).
5. **Regression guard**: bytecode-hash fast path; re-prove after
   quality-layer edits, alarm on equivalence break.
