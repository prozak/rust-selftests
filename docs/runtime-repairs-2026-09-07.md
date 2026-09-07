# Four Rust-only runtime repairs (2026-09-07)

This follows the ten [BTF/skeleton repairs](btf-repairs-2026-09-07.md).
It addresses `mptcp_subflow`, `netif_receive_skb`, `uprobe_multi_usdt`,
and `test_log_buf` against the unchanged kernel pin
`3ccdb07813829ba9487273e75d1cb238cfa774c1` and unmodified C consumers.

## Changes

`scripts/type_id.py` lowers explicitly annotated Rust `extern fn() -> u64`
calls to LLVM's standard `llvm.bpf.btf.type.id` intrinsic. The annotation
names a C type kind and name; the pass requires a matching TYPE_ID_TARGET
relocation in the pristine C object. It imports the type identity as debug
metadata. LLVM emits the relocation and libbpf resolves the kernel ID at
load time. No kernel numeric IDs or C program instructions are imported.
The pass supports integer, struct, union, enum32, and typedef roots and
rejects unsupported contracts. It runs only for annotated translations.

- `mptcp_subflow` now carries four type-ID relocations for three types and
  17 field-offset relocations. The list walk uses CO-RE container offsets,
  typed `bpf_rdonly_cast` calls, and direct field reads. The C `can_loop`
  guard replaces the previous arbitrary 16-subflow cap. Keeping the two
  checks out of line prevents rustc from merging their initial field
  polyfills and losing the debug path types before CO-RE lowering.
- `netif_receive_skb` replaces all pinned BTF IDs with 54 relocations for
  12 named types. The existing test flow and documented dead-comparison
  simplification are retained.
- `uprobe_multi_usdt` provides libbpf's two weak support-map exports.
  Compiler retention keeps them in one `.maps` section, and the optimizer
  explicitly preserves their public linkage. Map type, key/value sizes,
  entry limits, and weak linkage match the pristine C object. The specs
  map uses 304-byte values: twelve 24-byte argument records, a cookie,
  argument count, and explicit padding. The IP map uses 8-byte keys and
  4-byte values. The handler still counts all 50,000 USDT invocations.
- `test_log_buf` explicitly orders `good_prog` before `bad_prog`.
  `scripts/program_order.py` moves complete LLVM definitions before code
  generation without changing their bodies or debug metadata. libbpf can
  then produce the successful program's verifier log before stopping at
  the deliberate invalid access in `bad_prog`.

See [TRANSLATING.md](../TRANSLATING.md) for both new annotations.

## Validation

The consumer summary is top-level tests/subtests passed, not a ratio.
Each Rust run is followed serially by a pristine-C control. The log-buffer
consumer checks the exact four-instruction success log and the expected
out-of-bounds access at offset 16000 in a 16-byte map value.

| Object | Rust and C summary | Proof |
|---|---|---|
| mptcp_subflow | 1/4 PASSED | BAIL |
| netif_receive_skb | 1/0 PASSED | BAIL |
| uprobe_multi_usdt | 1/19 PASSED | EQUIV |
| test_log_buf | 2/9 PASSED | EQUIV |

All four Rust and C pairs have zero skipped subtests and zero failures.
Fresh proofs retain the previous verdicts: two EQUIV and two BAIL. No
waivers or verifier assertions changed. The corpus histogram remains
417 EQUIV / 120 BAIL / 33 TIMEOUT / 13 UNKNOWN / 13 NOPROGS, zero INEQUIV.

An LLVM integration check compiles a type-ID polyfill into an object and
applies its emitted relocation to two synthetic target BTF layouts. The
same object resolves `mptcp_sock` to ID 2 and ID 10 respectively. This
checks independence from BTF numbering; runtime validation uses the pinned
QEMU kernel, not a second booted kernel.

Sixteen new unit checks cover valid lowering, malformed or incompatible
declarations, unsupported polyfill uses, C relocation contracts, metadata
identity, unchanged unrelated IR, complete program ordering, and preserved
function bodies. The four translations have zero lint warnings.

## Evidence

Local ignored artifacts are under `nightly/a3-*20260907*`. The object
contract audit is `nightly/a3-object-contracts-20260907.json`; the LLVM
portability fixture and result are in `nightly/a3-portability-20260907/`.
Initial USDT attempts exposed separate retained `.maps` sections and then
internalized exports. A later successful zero-argument runtime run did
not reveal an undersized specs value; an independent C/Rust map comparison
caught that mismatch, and the layout was corrected and revalidated.
These exploratory logs are retained separately from final successful runs.

Final successful runtime logs are in `nightly/a3-final-20260907/` for
MPTCP and USDT, `nightly/a3-usdt-netif-20260907/` for netif, and
`nightly/a3-simple-20260907/` for log-buffer. The nonpassing USDT runs in
the latter two directories are exploratory, not the final USDT evidence.

The recorded gate becomes **585 PASS / 3 FAIL / 8 NO-ORACLE**. This step
refreshes four rows, retaining the other 592; it is not another full
nightly. The remaining failures are `tracing_struct`,
`tracing_struct_int128`, and `tracing_struct_many_args`. Their recorded C
controls also fail because the int128-argument target is missing from
module BTF; investigating that environment is the next step.

Stale failure logs for these four objects are removed from the tracked
gate directory; Git retains their history. The kernel pin and harness
source are unchanged, and all C objects and derived consumers are restored.

Closing `make ci-local` passes 161 tests, generated-document and kernel-pin
checks, zero lint errors with the same 127 existing warnings, and 596
cached guard rows with none missing. Every C/Rust object hash matches the
proof baseline. Full closeout evidence is in
`nightly/a3-ci-local-20260907.log` and `nightly/a3-results-20260907.json`.
