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
make ci-nightly NIGHTLY_OUT=nightly/my-run NIGHTLY_JOBS=8 NIGHTLY_BUILD_JOBS=4
```

The output directory must not already exist. Defaults are a UTC timestamp
under ignored `nightly/`, eight proof workers, and four build workers.
Both worker settings accept 1–8. QEMU consumers run **serially**; the
default guest size for this driver is four CPUs, overridable with
`QEMU_CPUS`. Allow a few hours for the full runtime gate.

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
6. Run every translation's QEMU consumers through `swap-and-test.sh`.
   A failed Rust run is retried with C to distinguish C-PASS, C-FAIL, and
   missing-consumer results. Successful Rust runs restore C and rebuild
   derived skeletons/test binaries without a second guest boot.
7. Restore C again, verify object hashes still match the proof inputs,
   and generate codegen results using this run's fresh proof baseline.
8. Restore C on exit, including failures and SIGINT/SIGTERM. An interrupted
   active swap also attempts to rebuild its C skeletons/test binary.
   Further interrupts are ignored during cleanup. A failed derived rebuild
   still attempts the final C object restore and marks the report ERROR.

Under QEMU, the consuming selftests check verifier acceptance/rejection
as well as runtime assertions. The old issue's standalone `make verify`
uses the parked UML kernel and is deliberately not invoked by this QEMU
pipeline. The kernel source and UML stack are not modified.

## Results and exit status

Each run retains `REPORT.md`, `summary.json`, individual stage logs,
per-object `proof/` and `runtime/` logs, `baseline-before.tsv`,
`baseline-after.tsv`, `proof-diff.json`, and `codegen.md`/`codegen.tsv`.
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
nightly itself never accepts them. This implements the local whole-stack
portion of issue #23. Scheduling and runner provisioning remain separate;
weekly kernel-gap reporting continues in its existing workflow.

## Runs

- 2026-10-12, the current baselines: the same kernel as the run
  below, with KVM. 588 PASS / 0 FAIL / 8 NO-ORACLE and one INEQUIV
  (`cpumask_success`); the runtime gate took 3 hours 27 minutes.
  `equiv/results/baseline.tsv` is newer than this run: six translations
  were changed afterwards and four waivers removed, which invalidates
  every row, so the proof sweep was repeated in full with
  `equiv/guard.py --all` (418 EQUIV, one more than the nightly). The six
  objects were re-run through the gate one at a time and pass.
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
