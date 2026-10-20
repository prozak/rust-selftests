# Whole-stack nightly validation

`make ci-nightly` runs a fresh validation of every `progs/*.rs` translation
on the existing pinned QEMU stack. It requires the same kernel, selftests,
LLVM, rust-bpf, Python/Z3, virtme-ng, and `/dev/kvm` access as normal local
validation. It does not fetch or rebuild the kernel, advance pins, publish
results, or update the committed proof/runtime baselines.

The kernel and the selftests output must come from
`scripts/build-qemu-kernel.sh` and `scripts/build-qemu-selftests.sh`, which
use the pahole in `pahole-commit` for both. Module BTF changes invalidate
the guard cache; nightly already proves every object freshly and records
module hashes.

```sh
make ci-nightly
make ci-nightly NIGHTLY_OUT=nightly/my-run NIGHTLY_JOBS=8 NIGHTLY_BUILD_JOBS=4 \
    NIGHTLY_GATE_WORKERS=8
```

The output directory must not already exist. Defaults are a UTC timestamp
under ignored `nightly/`, eight proof workers, four build workers and eight
QEMU gate workers. All three worker settings accept 1–8. The default guest
size for this driver is four CPUs, overridable with `QEMU_CPUS`. With eight
gate workers the runtime gate takes about 30 minutes, with four about an
hour; with one, serially in the shared selftests output, about three and a
half.

Do not run other builds, swaps, guards, or QEMU drivers against this
checkout/shared selftests output during nightly. An advisory lock prevents
two nightly runs in this checkout or against the same selftests output;
older drivers do not take those locks.
The runner takes its paths from `equiv/paths.py`, as the checker does, and
rejects an environment whose kernel-derived paths point outside
`KERNEL_SRC`. This includes `QEMU_KERNEL`: the guest must boot the pinned
tree's `arch/x86/boot/bzImage`, whose hash is recorded with the kernel
inputs.

## Pipeline

The driver sequences every stage even if the outer make uses `-j`:

1. `restore-all`, verify backups match installed C objects, check kernel pin.
2. Hermetic checks, force-rebuild all Rust objects with `make -B all`, lint.
3. Verify complete C/Rust object coverage and record object/tool/kernel hashes.
4. Fresh proof of **every** translation, with 180 seconds per object and
   30 seconds per solver query. It uses the guard's verdict classification,
   but never its hash-cache fast path or baseline-writing path.
5. Compare verdicts with `HEAD:equiv/results/baseline.tsv`. Save all changes,
   including added/removed rows; flag previously proved objects losing proof.
   Runtime verdicts are likewise compared with `HEAD:qemu/gate/baseline.tsv`
   (saved as `runtime-before.tsv`).
6. Run every translation's QEMU consumers through `swap-and-test.sh`,
   `NIGHTLY_GATE_WORKERS` objects at a time. Each run happens in a private
   overlayfs layer over the shared selftests output
   (`scripts/gate-overlay.sh`): the swapped object, the regenerated
   skeleton, the consuming test object and the relinked `test_progs` land
   in the worker's upper directory (about 40 MB per object), the guest
   mounts the same overlay before running `test_progs` (from a copy on
   the guest's tmpfs for the tests that resolve their own executable's
   path: mapped through overlayfs, the binary's own `vm_file` is the
   layer's file, and `bpf_iter`'s `task_vma` subtest, which compares
   `bpf_d_path()` of that mapping with `/proc/<pid>/maps`, fails for C
   and Rust alike), and the shared output is never written, so going
   back to C costs nothing. A worker's guest is booted once and runs the
   worker's objects in sequence (`scripts/gate-guest-loop`), the next
   object's layer being built while it runs the current one; anything but
   a PASS is rerun alone in a fresh guest, then the C object as before
   ([gate-runtime.md](gate-runtime.md)). The objects listed in
   `scripts/gate-serial` run afterwards, one at a time, in the shared
   output itself, as a single worker does: `fentry_recursive` and its
   target, whose stress test another guest's load perturbs (#52).
   `--gate-mode copy` (`scripts/gate-workers.sh`)
   gives each worker a trimmed copy of the output instead, about 0.7 GB
   each, for hosts without unprivileged user namespaces; `make
   clean-gate-workers` removes the copies.
   A failed Rust run is retried with C to distinguish C-PASS, C-FAIL, and
   missing-consumer results. Successful Rust runs restore C and rebuild
   derived skeletons/test binaries without a second guest boot. The
   verdicts are also written as `runtime-after.tsv`, in the gate
   baseline's format with this run's object and environment hashes and
   each object's wall seconds (the machinery is `scripts/qemu_gate.py`,
   shared with the incremental `scripts/gate.py`; the gate queue runs the
   objects the committed baseline recorded as longest first).
7. Restore C again, verify object hashes still match the proof inputs,
   and generate codegen results using this run's fresh proof baseline.
8. Restore C on exit, including failures and SIGINT/SIGTERM. An interrupted
   active swap also attempts to rebuild its C skeletons/test binary.
   Further interrupts are ignored during cleanup. A failed derived rebuild
   still attempts the final C object restore and marks the report ERROR.

The guests must run under KVM. `scripts/qemu-test-progs` opens `/dev/kvm`
before booting, and the driver stops the gate at the first guest log that
reports an emulated CPU (`QEMU TCG CPU`): the 2026-10-10 run and a
2026-10-15 run made while `/dev/kvm` was unusable showed that emulated
guests fail timing tests the C objects fail too (`test_tc_edt`,
`tracing_multi_*`) and Oops in `fentry_attach_stress` (#52, clean 10/10
under KVM), so an emulated run's verdicts are not evidence either way.

Under QEMU, the consuming selftests check verifier acceptance/rejection
as well as runtime assertions. The old issue's standalone `make verify`
uses the parked UML kernel and is deliberately not invoked by this QEMU
pipeline. The kernel source and UML stack are not modified.

## Results and exit status

Each run retains `REPORT.md`, `summary.json`, individual stage logs,
per-object `proof/` and `runtime/` logs, `baseline-before.tsv`,
`baseline-after.tsv`, `proof-diff.json`, `runtime-before.tsv`,
`runtime-after.tsv`, and `codegen.md`/`codegen.tsv`.
It also records the committed runtime table for comparison, source status
and diff, a source archive including new/uncommitted scripts, existing
known-bad-test exclusions, tool versions, and object/kernel/module hashes.
The report is refreshed during execution so partial progress survives.

Exit **0** means all required stages completed with no INEQUIV, checker
ERROR, loss of a previously proved result, runtime FAIL, or loss of a
previous runtime PASS to NO-ORACLE. Existing
BAIL/TIMEOUT/UNKNOWN/NOPROGS results are limitations, not successful proofs.
An existing or newly added NO-ORACLE is reported separately and does not
fail the pipeline. A PASS
consumer can still skip assertions and exercise sibling C programs; retain
its summary and read the complete log before claiming assertion coverage.
The existing `scripts/known-bad-tests` exclusions still apply.

Exit **1** means a gate failed or execution was incomplete. Proof failures
and normal test assertion failures allow later stages to collect evidence;
build, restoration, or other infrastructure failures stop dependent work.
Matching C/Rust environment failures still fail the nightly. They are not
waived automatically. Invalid CLI usage is exit **2** from the Python
runner (GNU make reports recipe failures with its own nonzero status).

Review and deliberately reconcile baselines after diagnosing changes;
nightly itself never accepts them. Once reviewed, `scripts/gate.py
--reseed nightly/<run>/runtime-after.tsv` copies the runtime verdicts into
`qemu/gate/baseline.tsv`, refusing any row whose recorded hashes no longer
describe the current objects or environment; the proof side is
`equiv/guard.py --reseed`. This implements the local whole-stack
portion of issue #23. Scheduling and runner provisioning remain separate;
weekly kernel-gap reporting continues in its existing workflow.

## Runs

- 2026-10-16 (later), the current baselines (`nightly/20261016-kvm-par8`,
  commit e84698e): the same kernel, eight overlay gate workers, `test_progs`
  run from the guest's tmpfs so the `bpf_iter_*` objects gate in parallel,
  rust-bpf master (PR #6 merged) as the build dependency. 602 PASS / 0 FAIL /
  8 NO-ORACLE for 610 objects and the same single INEQUIV; every verdict of
  the 597 shared objects matches the run below, and the 13 new objects (the
  `__contains` family of #53) bail in the proof. The gate took 31.5 minutes
  (1890 s), the proof sweep 20 minutes, the whole nightly 54 minutes. Proof:
  430 EQUIV / 117 BAIL / 36 TIMEOUT / 13 UNKNOWN / 13 NOPROGS.
- 2026-10-16: the same kernel, with four overlay
  gate workers. 589 PASS / 0 FAIL / 8 NO-ORACLE for 597
  objects (`normal_map_btf` is new) and the same single INEQUIV. The gate
  took 58 minutes against 3 hours 27 minutes serially; the host peaked at
  6.7 GB used during the proof sweep and 3.3 GB with the four guests up.
  Every runtime verdict matches the 2026-10-12 row, as did a 20-object
  comparison of overlay against serial runs made beforehand, once the
  `bpf_iter_*` objects had moved to `scripts/gate-serial`. Proof:
  430 EQUIV / 104 BAIL / 36 TIMEOUT / 13 UNKNOWN / 13 NOPROGS. The checker
  now fills `__kconfig` externs from the pinned kernel's `.config`, which
  proves `bpf_syscall_macro`, `test_ctx`, `test_global_map_resize`,
  `test_probe_user` and `timer_interrupt`, and lets `arena_spin_lock` and
  `bpf_cubic` run to the 180-second limit where they used to bail.
- 2026-10-12: the same kernel as the run below, with KVM. 588 PASS / 0 FAIL / 8 NO-ORACLE and one INEQUIV
  (`cpumask_success`); the runtime gate took 3 hours 27 minutes.
  `equiv/results/baseline.tsv` is newer than this run: six translations
  were changed afterwards and four waivers removed, which invalidates
  every row, so the proof sweep was repeated in full with
  `equiv/guard.py --all` (418 EQUIV, one more than the nightly). The six
  objects were re-run through the gate one at a time and pass.
  The sweep was repeated once more after the checker gained a
  `bpf_rdonly_cast` model and three translations were converted to it
  (425 EQUIV / 110 BAIL / 34 TIMEOUT / 13 UNKNOWN / 13 NOPROGS, the same
  single INEQUIV).
- 2026-10-10: all 596 runtime rows on unpatched bpf-next built by the
  scripts above. 581 PASS / 7 FAIL / 8 NO-ORACLE and one INEQUIV. The
  guests ran emulated, without KVM, which went unnoticed until afterwards,
  and the gate took 7.6 hours. Four of the failures were timing checks the
  C objects failed too, two were guest panics during boot, and one was a
  stale kernel BTF id in `test_tc_tunnel`, fixed in `3296ed8`. None of
  them recurs in the 2026-10-12 run. `scripts/qemu-test-progs` now refuses to start
  without a usable `/dev/kvm`.
- [2026-09-07](history/ci-nightly-results-2026-09-07.md): stopped at
  290/596 on a guest panic caused by a kernel and a test module built with
  different pahole versions.
- [2026-09-06](history/ci-nightly-results-2026-09-06.md): the first
  complete run.
