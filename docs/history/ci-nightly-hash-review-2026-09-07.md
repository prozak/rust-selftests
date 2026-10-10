# Nightly implementation and object-hash review (2026-09-07)

The five Rust object hashes changed by the September 6 forced rebuild are
explained by the LLVM bitcode-to-text round trip introduced in Phase 3
commit `8405b2c`. That build step supports explicitly marked raw BPF ABIs.
None of these five translations uses its `BPF_NAKED` transformation.

For each object, running `llc` directly on the current
`bld/<name>-ksyms.bc`, followed by the existing object-copy and four BTF
postprocessing steps, reproduces the **old committed MD5 exactly**. The
normal build instead disassembles that bitcode to textual LLVM IR before
invoking `llc`.

Only `.BTF` differs between the reproduced old object and the nightly
object. In each case, two forward declarations exchange type IDs; their
pointer references and the two associated string-table entries move with
them. Applying exactly those changes to the old `.BTF` reproduces the
new `.BTF` byte for byte. All other section contents and section
type/flags/size/link/info/entry-size fields match, including instructions,
data, symbols, relocations, DWARF, and `.BTF.ext`.

| Object | Old Rust MD5 | Nightly Rust MD5 | Exchanged FWD IDs | Proof |
|---|---|---|---|---|
| bpf_iter_netlink | 04a600135f02b675594729acc12951a8 | 9ff419a34f352dc32d7853282cebdfa3 | 35, 36 | BAIL |
| bpf_iter_tcp4 | d1a7ad05def01a7bb0e6a7e2e568f702 | e456e601b222667b6e19eeeed9beed72 | 71, 72 | BAIL |
| bpf_smc | 49cef6c750649d19aaafe0961165ff44 | c3f4db77736cc8ef4a68d696e0529767 | 60, 61 | EQUIV |
| btf_dump_test_case_syntax | 0f18dbd90aaa7ba3da96e06926d90fce | 57e7986737c2144b7259a2535f373f97 | 98, 99 | NOPROGS |
| test_task_local_data | 89c4983f71dd09f877b726a22205170c | 1a50d9d58d943d3d43b0b991f2536044 | 52, 53 | TIMEOUT |

All five runtime consumers passed in the saved full run. Their proof
verdicts are unchanged; BAIL, NOPROGS, and TIMEOUT remain limitations.
The review deliberately refreshes only these five Rust-hash fields in
`equiv/results/baseline.tsv`. C hashes, tool hashes, verdicts, and details
remain unchanged. The nightly runner still never updates baselines.

Local reproduction objects, raw BTF dumps, per-object BTF diffs, and the
machine-readable audit are retained under ignored
`nightly/review-20260907/`. The original full-run artifacts remain intact
under `nightly/20260906-full/`.

## Runner review

The review also closes two recovery/configuration gaps:

- Reject an alternate `QEMU_KERNEL` boot image and record the pinned
  `bzImage` hash with the kernel inputs.
- Attempt final C object restoration even if derived recovery cannot
  launch or exits unsuccessfully. Report cleanup failure as ERROR;
  ignore additional SIGINT/SIGTERM during cleanup and restore the prior
  signal handlers afterward. Handle process-group exit at a timeout.

`make ci-fast` passes 133 tests, including alternate-image rejection,
image-hash recording, derived-restoration exceptions/failures, a second
signal during cleanup, and final-restoration exceptions. The recorded
full run predates these review fixes; its 127-test count remains the
historical result. No full rebuild or QEMU gate was repeated for this
review.

Closing `make ci-local` passes: 133 tests, generated-document and kernel-pin
checks, zero lint errors with 127 existing warnings, and all 596 proof
rows cached with zero missing objects. All C objects are restored.
