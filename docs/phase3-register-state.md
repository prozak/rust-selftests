# Phase 3: unreadable return registers and the prover boundary

The first Phase 3 guard reported INEQUIV for four programs in
`aggregate_ret_func` and `aggregate_ret_kfunc`, with return witnesses
`C=4294967295 rust=0`. Both objects passed the C driver's rejection
assertions in QEMU.

Comparing each function's instruction bytes after resolving call
relocations to function names shows identical streams. The three affected
subprogram bodies are also identical. Section ordering differs, so raw
call relocation offsets alone are not a meaningful comparison.

| Program | Instructions in both objects |
|---|---|
| aggregate_ret_global_fail | `call global_agg_bad; r0 = r2; exit` |
| aggregate_ret_global_ptr_fail | `call global_agg_bad_ptr; r0 = r2; exit` |
| aggregate_ret_static_uninit_fail | `call static_agg_no_r2; r0 = r2; exit` |
| aggregate_ret_kfunc_small_no_r2 | `r1 = 0; r2 = 0; call bpf_kfunc_call_test_ret_ii; r0 = r2; exit` |

`global_agg_bad` and `static_agg_no_r2` contain `r0 = 0; exit`.
`global_agg_bad_ptr` contains `r0 = 0; r2 = r10; exit`.
The test contracts reject uninitialized R2, a stack pointer in R2, or a
read of R2 after a kfunc whose return fits in R0.

The executor currently restores the caller's registers across a subprogram
return except for R0; the R0:R2 aggregate ABI is not fully modeled. It
also assigns independent symbolic values to helper-clobbered registers.
Consequently these comparisons contained `uninit_A_r2` versus
`uninit_B_r2`, or independent `clobber_A_*` / `clobber_B_*` values.
Z3 can distinguish those values even for identical instructions. This is
an unsupported execution state, not evidence of a translation difference.

`check_program` now reports BAIL when a satisfiable comparison still
depends on such private register symbols after simplification. It does
not merge those symbols, prove the programs equivalent, alter their
instructions, or waive their assertions. Full modeling of aggregate
returns remains future prover work.

Hermetic tests cover uninitialized and post-helper register reads and
confirm that a real constant-return difference still reports INEQUIV.
Three existing branch-comparison fixtures also needed R0 initialized on
their taken branch: they previously relied on uninitialized R0 for their
counterexample. Their INEQUIV assertions remain, now over defined return
values on both paths.
