# First whole-stack nightly run (started 2026-09-06)

The complete 596-object run finished against unchanged bpf-next pin
`3ccdb07813829ba9487273e75d1cb238cfa774c1`. Every proof and runtime verdict
matches the committed baseline tables at `d600061`. This is a fresh rebuild,
proof sweep, and serial runtime gate, replacing the previous mixed-age
validation evidence with one complete measurement.

Run: `make ci-nightly NIGHTLY_OUT=nightly/20260906-full`.
The local [full report](../nightly/20260906-full/REPORT.md), JSON, per-object
logs, baseline snapshots, and source/tool/input records remain in that
ignored directory. The [runner guide](ci-nightly.md) documents reproduction
and exit semantics. No committed baseline or codegen report was rewritten.

## Results

| Stage | Result |
|---|---|
| Forced Rust rebuild | All 596 objects; 116 seconds |
| Lint | Zero errors, 127 existing warnings |
| Fresh proof sweep | 417 EQUIV / 120 BAIL / 33 TIMEOUT / 13 UNKNOWN / 13 NOPROGS |
| Proof regressions | Zero INEQUIV, zero verdict changes, zero EQUIV downgrades |
| Fresh QEMU verifier/runtime gate | 571 PASS / 17 FAIL / 8 NO-ORACLE; zero verdict changes |
| Codegen | 1,222 program pairs; C 26,309 instructions, Rust 26,707 (1.015x) |
| Final implementation tests | 127 hermetic tests pass; generated semantics and syntax checks pass |
| Final restoration/integrity | All C objects restored; all 596 C/Rust hashes match proof inputs; harness clean |

The proof sweep took 18 minutes 34 seconds with eight workers. Serial
runtime validation took 3 hours 23 minutes. Total stage time was about
3 hours 44 minutes. QEMU consumers supplied the verifier checks; the
parked UML verifier was not invoked.

The driver returned **1**, surfaced by GNU make as exit **2**, because
17 runtime tests fail. Every stage completed, including codegen and final
restoration; this was not an infrastructure abort. Existing failures were
not waived. Fifty-three PASS rows include skipped assertions. Their
consumer summaries can also include sibling C programs, so PASS is not a
claim that every translated assertion ran.

## Runtime failures

| Object | Fresh C result | Rust result |
|---|---|---|
| kprobe_multi_sleepable | PASS | Fails before runtime summary |
| ksym_race | PASS | Fails before runtime summary |
| metadata_unused | PASS | Fails before runtime summary |
| metadata_used | PASS | Fails before runtime summary |
| mptcp_subflow | PASS | Runtime assertion failure |
| netif_receive_skb | PASS | Runtime assertion failure |
| test_d_path_check_rdonly_mem | PASS | Fails before runtime summary |
| test_d_path_check_types | PASS | Fails before runtime summary |
| test_ksyms | PASS | Fails before runtime summary |
| test_ksyms_btf_null_check | PASS | Fails before runtime summary |
| test_log_buf | PASS | Runtime assertion failure |
| test_ptr_untrusted | PASS | Fails before runtime summary |
| tracing_struct | FAIL | Matching environment failure |
| tracing_struct_int128 | FAIL | Matching environment failure |
| tracing_struct_many_args | FAIL | Matching environment failure |
| uprobe_multi_usdt | PASS | Runtime assertion failure |
| xdp_dummy | PASS | Runtime assertion failure |

All three tracing C logs report that
`bpf_testmod_test_int128_arg` is absent from kernel/module BTF.

The five objects previously recorded with C-NOCONSUMER (`ksym_race`, both
`test_d_path_check_*` objects, `test_ksyms`, and
`test_ksyms_btf_null_check`) now have successful C consumer runs. Their
Rust verdicts remain FAIL, but the oracle evidence is stronger.

## Rebuild and implementation details

All C hashes and the proof tool hash match the committed baseline. Five
Rust hashes changed after the forced rebuild: `bpf_iter_netlink`,
`bpf_iter_tcp4`, `bpf_smc`, `btf_dump_test_case_syntax`, and
`test_task_local_data`. Their proof verdicts are unchanged and all five
pass their runtime consumers. The cause of those byte-level build
changes was not established; the committed hash baseline remains intact
for deliberate review.

The run began while final lock, reporting, and diagnostic hardening was
being finished. The final implementation passes 127 hermetic tests.
All 596 saved proof logs were subsequently checked with the final verdict
classifier, with no classification changes, and the final report renderer
was applied without changing any outcomes. The run-start source archive,
final implementation overlay, and final audit are retained separately as
`sources.tar.gz`, `implementation-final.tar.gz`, and `final-audit.json`.

The local pipeline is implemented. Scheduling/runner provisioning remains
separate work; the existing weekly kernel-gap workflow is unchanged.
The next useful work is diagnosing and fixing the 14 Rust-only failures
and addressing the three module-BTF environment failures.
