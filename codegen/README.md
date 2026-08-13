# Codegen study: rustc vs clang on BPF

What does the rust-bpf pipeline emit where clang emits something else, and
which of those differences are worth fixing in the compiler? This is a
codegen question, not a correctness one — `equiv/` answers correctness.

## Why the numbers mean something

The corpus is the set of programs `equiv/` has **proved semantically
equivalent** in both builds. Both objects are known to compute the same
thing, so every instruction of difference is attributable to the compiler
rather than to a translation choice. That is a rare thing to have, and it
is the whole reason this comparison is worth running.

Two exclusions keep it honest:

- **Waived programs are dropped.** An object can be verdict-EQUIV while one
  of its programs is waived, and a waived program is by definition *not*
  doing the same thing in both builds. `test_core_reloc_type_based` would
  otherwise show up as rustc's biggest "win" at -151 instructions, which is
  really the translation taking the C source's own skip branch.
- **Counts follow bpf2bpf calls into `.text`.** Otherwise a translation
  that leaves a helper out-of-line looks *smaller* than one that inlines
  it. rustc and clang disagree about inlining often enough for this to
  matter.

## Usage

```sh
../z3-venv/bin/python codegen/compare.py            # -> REPORT.md, pairs.tsv
../z3-venv/bin/python codegen/compare.py --all      # include unproved pairs
../z3-venv/bin/python codegen/compare.py --show test_lwt_ip_encap:encap_gre6
```

`--show` prints the two instruction streams side by side, which is how each
finding below was pinned down.

## Files

- `insns.py` — instruction decode, classification, whole-program traversal.
  Classification is deliberately coarse: the point is to say *where* the
  extra instructions went (frame traffic? branches? sub-register moves?),
  since that is what names a compiler problem.
- `compare.py` — pairs programs, computes metrics, generates the report.
- `REPORT.md` — generated. Regenerate rather than edit.
- `pairs.tsv` — generated, one row per program pair, for ad-hoc analysis.
- `FINDINGS.md` — hand-written analysis: what the numbers mean and what to
  do about it.

## Caveats

- Instruction *count* parity does not prove instruction-level identity; the
  per-kind histogram is the real signal.
- The corpus skews simple: programs that bail or time out in the prover are
  excluded, and those are the complex ones.
- Static instruction counts are not run-time cost. A tight verifier
  instruction budget makes size matter on its own, but nothing here
  measures cycles.
