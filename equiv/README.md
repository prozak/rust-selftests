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

Soundness stance: unsupported constructs BAIL rather than being approximated,
so EQUIV verdicts only rest on modeled semantics. Known deliberate
assumptions: probe-reads never fault; LD_IMM64 global/map pointers are
non-NULL; both programs see the same kernel memory snapshot.

## Verdict sweep (2026-08-05, v1, no helper support)

550-program corpus: see the session results dir; headline: 83 EQUIV before
artifact fixes, dominant BAIL cause is `call` (helpers) — that is v1.1.

## Roadmap

1. **v1.1 helpers**: pure-read helpers as a shared per-call-index oracle
   (`ret = oracle(helper_id, index)`); side-effecting helpers as an observable
   call trace — sequence equality of (helper, args) with pointer args compared
   by (region, offset) for shared regions, later by pointed-to bytes using
   key/value sizes parsed from map BTF defs.
2. **CO-RE application**: apply `.BTF.ext` relocations against the pinned
   vmlinux BTF (like libbpf) before lifting, unlocking the CORESKIP class.
3. **Regression guard**: bytecode-hash fast path; re-prove after quality-layer
   edits (policy linter / clippy hardening), alarm on equivalence break.
4. Atomics, endian ops, bounded-loop widening, subprog calls (inline at
   call site).
