# BTF and skeleton compatibility repairs (2026-09-07)

Both repair waves from the post-nightly regroup are complete against the
unchanged bpf-next pin `3ccdb07813829ba9487273e75d1cb238cfa774c1`.
Ten previously failing Rust objects now pass their unmodified C consumers.
Each was tested serially in QEMU with a passing pristine-C control.
No assertions or exclusions were changed.

## Changes

The first wave fixes the C types exposed through generated skeletons:

- `metadata_used`, `metadata_unused`, and `test_ptr_untrusted` select the
  existing C-char annotation for their character arrays.
- `xdp_dummy` uses the same annotation for the license array, satisfying
  the exact `char[4]` DATASEC dump assertion.
- `kprobe_multi_sleepable` uses the new explicit `BTF_C_VOID` annotation
  so its `user_ptr` global appears as `void *`. Only pointers to Rust's
  `c_void` enum are repointed to BTF void; other types stay unchanged.

The second wave fixes missing external data-variable declarations:

- `scripts/ksym_vars.py` emits BTF-enabling LLVM debug declarations for
  explicitly selected `BTF_KSYM` externs. It reads type/qualifier and weak
  linkage information from the pristine C object's `.ksyms` variables.
- It preserves scalar width/signedness and const qualifiers, and emits
  named aggregate descriptors for kernel type matching. It does not
  import C program instructions or aggregate fields; field accesses
  still use the translation's own CO-RE information.
- The pass runs before internalization/optimization, only for annotated
  objects. It rejects missing/defined symbols, existing section/debug
  metadata, unsupported types, and mismatched integer widths.
- `ksym_race`, both `test_d_path_check_*` objects, `test_ksyms`, and
  `test_ksyms_btf_null_check` opt into this mechanism. The deliberately
  absent weak symbol in `test_ksyms` now resolves to zero at runtime.

## Runtime and proof results

The summary column is the harness's top-level tests/subtests passed,
not a ratio. All listed Rust and C runs have zero skips and zero failures.
Consumer runs can include sibling C programs.

| Object | Rust and C summary | Proof |
|---|---|---|
| metadata_unused | 3/4 PASSED | EQUIV |
| metadata_used | 3/4 PASSED | EQUIV |
| test_ptr_untrusted | 1/0 PASSED | EQUIV |
| kprobe_multi_sleepable | 3/23 PASSED | EQUIV |
| xdp_dummy | 12/66 PASSED | EQUIV |
| ksym_race | 1/2 PASSED | EQUIV |
| test_d_path_check_rdonly_mem | 2/6 PASSED | EQUIV |
| test_d_path_check_types | 2/6 PASSED | BAIL |
| test_ksyms | 3/8 PASSED | EQUIV |
| test_ksyms_btf_null_check | 1/6 PASSED | EQUIV |

The three negative tests were also run with verbose verifier output.
Rust and C reach the intended rejection paths:

- `test_d_path_check_rdonly_mem`: `bpf_d_path` cannot write through its
  second argument, which is `rdonly_mem`.
- `test_d_path_check_types`: `bpf_ringbuf_submit` receives `rdonly_mem`
  where `ringbuf_mem` is required.
- `test_ksyms_btf_null_check`: dereferencing the unchecked `rq` pointer
  fails with `invalid mem access 'ptr_or_null_'`.

All ten objects were re-proved with at most eight workers after restoring
the C objects. Their nine EQUIV and one BAIL verdicts are unchanged.
The corpus proof histogram remains 417 EQUIV / 120 BAIL / 33 TIMEOUT /
13 UNKNOWN / 13 NOPROGS, with zero INEQUIV.

The recorded runtime gate becomes **581 PASS / 7 FAIL / 8 NO-ORACLE**.
The other 586 rows were retained; this was not a repeat full nightly.
The seven failures are `mptcp_subflow`, `netif_receive_skb`, `test_log_buf`,
`uprobe_multi_usdt`, and the three tracing objects whose C controls also
fail because the int128-argument target is missing from module BTF.

## Evidence and checks

The final successful Rust/C runs are retained under ignored
`nightly/a2-types-20260907/`, `nightly/a2-negative-20260907/`, and
`nightly/a2-extern-positive-20260907/`. The initial external-wave logs
remain under `nightly/a2-externs-20260907/`; all its per-object tests
passed, but an edit to the temporary driver while it ran caused a trailing
shell parse error. C restoration was independently verified, and all five
external objects were subsequently validated with the corrected driver.

The existing nightly artifacts are preserved. Stale tracked failure logs
for these ten now-passing objects are removed; Git retains their history.

Closing `make ci-local` passes: 145 tests, generated-document and kernel-pin
checks, zero lint errors with 127 existing warnings, and all 596 proof rows
cached with no missing objects. All current C/Rust object hashes match the
proof baseline, and all C objects are restored. The harness source and
kernel pin are unchanged. The machine-readable object hashes, consumer
summaries, and gate counts are in `nightly/a2-results-20260907.json`.
