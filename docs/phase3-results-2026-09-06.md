# Phase 3 validation (2026-09-06)

All 19 remaining Phase 3 objects are translated against bpf-next `3ccdb078`.
Coverage is now 596 of 1008 upstream C objects. `make status` reports
596/1009 in the patched harness tree, which adds the untranslated
`btf__core_reloc_type_id___dup_compat_types` fixture. Five fixtures/configuration-specific
objects are explicitly listed as non-targets by `make status`.

Runtime validation: 18 passing consumer runs and one matching C/Rust
environment failure. A passing consumer can include skipped assertions;
the limitations below are part of the result.

The full 596-object guard passed: **417 EQUIV / 120 BAIL / 33 TIMEOUT /
13 UNKNOWN / 13 NOPROGS**, zero INEQUIV and no EQUIV downgrades.
The 19 additions contribute 13 EQUIV and six BAIL. Compared with Phase 2,
`bpf_loop` changed TIMEOUT → BAIL and `test_l4lb_noinline` changed
TIMEOUT → UNKNOWN; all other old verdicts are unchanged. This guard uses
its default 180-second object cap, versus the seeded sweep's 120 seconds.
Neither changed verdict is a proof. See the
[complete sweep](../equiv/results/sweep-2026-09-06-596.tsv) and hashed baseline.

`make ci-local` passed: 103 hermetic tests, Python compilation, generated
SEMANTICS.md consistency, kernel-pin check, lint, and all 596 cached guard
rows with zero missing objects. C objects are restored.

Corpus lint: zero errors and 127 existing warnings across 596 translations;
the 19 additions have zero warnings. The recorded overall runtime gate is
571 PASS / 17 FAIL / 8 NO-ORACLE. The old 577 runtime rows were retained,
not rerun in this phase.

| Object | Proof | Runtime | Consumer summary / limitation |
|---|---|---|---|
| fentry_sleepable | EQUIV | PASS | Summary: 1/16 PASSED, 0 SKIPPED, 0/0 FAILED |
| aggregate_ret_target | EQUIV | PASS | Summary: 1/16 PASSED, 0 SKIPPED, 0/0 FAILED |
| freplace_ret_pair | EQUIV | PASS | Summary: 1/16 PASSED, 0 SKIPPED, 0/0 FAILED |
| tracing_struct_int128 | EQUIV | FAIL | Summary: 0/3 PASSED, 0 SKIPPED, 1/1 FAILED; C-FAIL: bpf_testmod_test_int128_arg absent from module BTF |
| kfunc_implicit_args_tracing | EQUIV | PASS | Summary: 1/0 PASSED, 0 SKIPPED, 0/0 FAILED |
| ksock_lsm | BAIL | PASS | Summary: 2/1 PASSED, 0 SKIPPED, 0/0 FAILED |
| ksock_wq | BAIL | PASS | Summary: 1/0 PASSED, 0 SKIPPED, 0/0 FAILED |
| sock_read_xattr | EQUIV | PASS | Summary: 1/4 PASSED, 0 SKIPPED, 0/0 FAILED |
| struct_ops_arena | EQUIV | PASS | Summary: 1/3 PASSED, 0 SKIPPED, 0/0 FAILED |
| struct_ops_arena_attach | EQUIV | PASS | Summary: 1/3 PASSED, 0 SKIPPED, 0/0 FAILED |
| test_tc_qevent | EQUIV | PASS | Summary: 1/0 PASSED, 2 SKIPPED, 0/0 FAILED; both traffic subtests SKIP (environment); object load passes |
| arena_mem_usage | EQUIV | PASS | Summary: 1/0 PASSED, 0 SKIPPED, 0/0 FAILED |
| arena_kfunc_jit | EQUIV | PASS | Summary: 129/2513 PASSED, 26 SKIPPED, 0/0 FAILED; all three JIT-disassembly programs SKIP (harness lacks LLVM disassembly support) |
| aggregate_ret_func | BAIL | PASS | Summary: 2/21 PASSED, 2 SKIPPED, 0/0 FAILED |
| aggregate_ret_kfunc | BAIL | PASS | Summary: 2/21 PASSED, 2 SKIPPED, 0/0 FAILED |
| aggregate_ret_kfunc_arena | EQUIV | PASS | Summary: 2/21 PASSED, 2 SKIPPED, 0/0 FAILED; upstream dummy carries needs LLVM 23 skip; current build uses LLVM 22 |
| arena_kfunc | BAIL | PASS | Summary: 129/2513 PASSED, 26 SKIPPED, 0/0 FAILED; seven active programs pass; upstream stack-argument dummy SKIP |
| tailcall_callback | EQUIV | PASS | Summary: 1/40 PASSED, 0 SKIPPED, 0/0 FAILED |
| test_global_percpu_data | BAIL | PASS | Summary: 2/8 PASSED, 0 SKIPPED, 0/0 FAILED |

The consumer summaries include sibling C objects; they are not counts
of newly translated programs. Each Rust object was swapped in separately,
then all C objects were restored before proving.

## Findings

- Raw aggregate-return tests needed a narrow LLVM naked-function lowering
  step to keep Rust BTF signatures and exact R0:R2 assembly.
- Arena-tagged aggregate fields and pointer arrays now retain TYPE_TAG
  metadata; char storage and anonymous global structs can match their C BTF.
- The per-CPU test runs both normal and light skeletons successfully.
- Four initial INEQUIV program results exposed independent unreadable
  register symbols in the prover. See the
  [instruction-level diagnosis](phase3-register-state.md).
  They are treated as an explicit BAIL boundary,
  with rejection assertions preserved and no new waivers.

## Deferred backlog from the bump plan

- Verifier objects: `verifier_aggregate_ret`, `verifier_zext`,
  `verifier_subprog_insn_stats`, `verifier_percpu_addr`, `verifier_mem_size_reg`,
  `verifier_map_lookup_refine`, `verifier_ptr_to_buf` (seven objects).
- Negative objects: `bpf_qdisc_fail__untrusted_write`, `ksock_lsm_verifier`,
  `struct_ops_arena_fail` (three objects).
- Phase 4: automated kernel-gap reporting and later weekly CI integration.
- Portable CO-RE type-ID emission and the pre-existing gate failures remain
  separate work. LLVM 23 aggregate-arena bodies require a toolchain bump;
  the current translation deliberately matches the pinned C fallback.

Reproduce the new-object gate with `bash scripts/validate-phase3.sh`.
Its nonzero exit retains the documented tracing environment failure.
The script builds and lints the selected objects, runs consumers serially,
restores C objects on exit, and retains a nonzero status for runtime failures.
Logs are retained locally under `qemu/phase3/`; the matching tracing failure
logs are also retained with the main gate artifacts.
