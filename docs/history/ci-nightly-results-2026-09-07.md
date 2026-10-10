# Post-repair nightly attempt (2026-09-07)

The tracing repair was pushed as `0912c3f`, and
[GitHub CI passed](https://github.com/prozak/rust-selftests/actions/runs/34168973598).
The fresh whole-stack nightly then exposed regressions in the regenerated
module BTF and an INEQUIV result previously hidden by a proof timeout.
It ended **ERROR after 290 of 596 runtime rows**. This is an incomplete,
failing run; the recorded 588 PASS / 0 FAIL / 8 NO-ORACLE table is not a
validated result for the repaired whole stack.

Run: `make ci-nightly NIGHTLY_OUT=nightly/20260907-post-repairs
NIGHTLY_JOBS=8 NIGHTLY_BUILD_JOBS=4`. The kernel pin remains
`3ccdb07813829ba9487273e75d1cb238cfa774c1`.
Local evidence is in ignored `nightly/20260907-post-repairs/`, including
`REPORT.md`, `summary.json`, per-object logs, input hashes, baseline
snapshots, and `closeout-audit.json`. The audit computes runtime changes
for this incomplete run; the driver's runtime-diff field is only populated
after a complete runtime loop and is empty here.

## Results

| Stage | Result |
|---|---|
| Hermetic checks | 168 tests pass; syntax and generated-document checks pass |
| Forced Rust rebuild | All 596 objects; 115.8 seconds |
| Lint | Zero errors, 127 existing warnings |
| Fresh proof | 417 EQUIV / 120 BAIL / 32 TIMEOUT / 13 UNKNOWN / 13 NOPROGS / 1 INEQUIV; 1,113.2 seconds |
| Proof changes | `cpumask_success`: TIMEOUT to INEQUIV; no EQUIV downgrades |
| Runtime before abort | 276 PASS / 10 FAIL / 4 NO-ORACLE across 290 rows |
| Remaining runtime/codegen | 306 rows and codegen did not run |
| Cleanup | Active C rebuild and final restore pass; all 596 C/Rust hashes match the run inputs |

Every runtime FAIL was previously PASS, and every failing Rust run has a
failing C control. All four observed NO-ORACLE rows were already recorded
as NO-ORACLE. PASS may include skipped assertions and sibling C programs.
No committed baseline was updated, no failure was waived, and no source
or installed input was changed during the nightly.

## Module BTF regressions

| Objects | Observed failure |
|---|---|
| `iters_css`, `iters_css_task`, `iters_num`, `iters_task` | Shared `iters` consumer rejects `iter_next_trusted` and `iter_next_rcu`; module kfunc parameter types fail compatibility with kernel `vm_area_struct` and `task_struct` |
| `kfunc_call_destructive`, `kfunc_call_fail`, `kfunc_call_test` | Shared kfunc consumer fails in both Rust and C runs |
| `nested_acquire`, `nested_trust_success` | Module kfunc calls reject nested socket types in both runs |
| `struct_ops_assoc` | Both guests panic in `bpf_prog_get_assoc_struct_ops`, called from `bpf_kfunc_multi_st_ops_test_1_assoc`; exit 255, no test summary |

The panic causes the driver to stop with its generic C restoration/rebuild
error. The later cleanup rebuild succeeds, so the final shared output has
restored C objects and derived consumers. No QEMU process remains.

The new pahole revision encodes multidimensional arrays as chained ARRAY
types. The existing kernel BTF was generated with flattened arrays.
A deep comparison of the duplicated `task_struct` and `vm_area_struct`
graphs reaches `lru_zone_size`: kernel BTF has a flat length of 20, while
the new module has an outer length of 4 and an inner dimension of 5.
This representation mismatch obstructs deduplication against kernel BTF;
the regenerated module carries local copies of types that the previous
module referenced through its distilled base. Matching immediate function
argument names/sizes and executable bytes did not detect this incompatibility.
`--flat_arrays` in this pahole source controls printing, not BTF encoding.
The type comparison is saved as `module-type-diff.json`.

After the nightly stopped, an isolated all-C control temporarily installed
the saved previous module. With the same four-CPU guest configuration,
`iters,struct_ops_assoc` passes **2/99, zero skips and failures**, including
the consumer that panicked. This confirms a module-generation regression.
The control is retained as `old-module-c-control-4cpu.log`; the regenerated
module was restored afterward and its hash rechecked. A preliminary control
with the runner's default CPU count also passed and is retained separately.
The precise cause of the implicit-argument failure behind the panic still
needs investigation; it is not established solely by the array comparison.

## Proof timeout finding

The current nightly runs the checker unbuffered and preserves INEQUIV
output even when the object later times out. `cpumask_success` emits:

- `test_alloc_free_cpumask`: observable `g:err` differs.
- `test_firstand_nocpu`: observable `trace` differs.

Its C/Rust/tool hashes are unchanged. The guard's `prove()` discards partial
output on `TimeoutExpired`; the previous full nightly used buffered output
and retained an empty timeout log. Thus previous TIMEOUT results could hide
these findings. The fresh nightly correctly fails on them even though its
EQUIV-downgrade flag is false.

Read-only disassembly shows C masking the `bpf_cpumask_empty` return with
`& 1`, while Rust tests the full 32-bit return. The checker models generic
kfunc returns as unconstrained scalars. A focused ABI/model investigation
is needed before labeling the findings translation bugs or false positives.
The runtime consumer passes **1/36 with zero skips/failures**, which does
not discharge the symbolic finding. No checker or translation was changed.

## Rebuild hash and integrity

Only `test_tcp_custom_syncookie` changes its Rust object hash:
`46229eacc416d57dfaa6fa44ea7d9b5f` to
`c3767f6fde5e12db85b0773063cf86a8`. Direct bitcode codegen reproduces the
old hash exactly. The nightly object's only changed section is `.BTF`:
FWD IDs 49/50 (`IpHdr`/`EthHdr`), their pointer references, and their strings
exchange. Applying those edits reconstructs the new BTF byte-for-byte.
Other section contents and metadata match. Evidence is in `hash-review/`.
The proof remains BAIL; its runtime row was not reached, so the committed
hash is deliberately left unchanged.

All C hashes and the proof-tool hash match the committed baseline. Closing
audits confirm all 596 C/Rust hashes match the nightly inputs, all C backups
are restored, kernel/module hashes are unchanged after the control, and the
harness and Rust toolchain source checkouts remain clean.

Next: restore kernel/module BTF compatibility while retaining the int128
fix; validate iterator, kfunc, nested-type, struct-ops, and tracing controls.
Also preserve partial INEQUIV output in the guard and investigate the
cpumask boolean-return finding. Then rerun the whole-stack nightly before
scheduling or claiming a clean gate.
