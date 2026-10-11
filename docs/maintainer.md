# Maintainer guide

How to run subsets of the corpus, read the results and keep the build tree
healthy. The [README](../README.md) covers what the repo is and how to
build everything once; this assumes `.build/` exists.

All commands run from the repository root. Paths come from
`scripts/paths.sh` (shell), `equiv/paths.py` (Python) and the Makefile,
which apply the same defaults under `BUILD_DIR` (`.build/`) and honour the
same overrides: `KERNEL_SRC`, `SELFTESTS_OUTPUT`, `LLVM_PREFIX`,
`VMLINUX_BTF`, `QEMU_KERNEL`, `RUSTBPF`. Guest sizing and timeouts:
`QEMU_CPUS` (8), `QEMU_MEM` (4G), `QEMU_TIMEOUT` (600 s), `VNG` (`vng`
on `PATH`, else `.build/vng-venv/bin/vng`).

## Running all the Rust tests in QEMU

```sh
scripts/qemu-verify.sh                      # every progs/*.rs
scripts/qemu-verify.sh fentry_test atomics  # just these
```

`qemu-verify.sh` takes its paths from `scripts/paths.sh` and for each
program runs, serially:

- `make test-<name>` — build `bld/<name>.bpf.o`, install it over
  `<name>.bpf.o` in the selftests output, regenerate the affected
  skeletons and `test_progs` **with the kernel's own Makefile**, and run
  the affected tests in the QEMU guest;
- `make restore-<name>` — put the pristine C object back and run the same
  tests again, which both leaves the output dir clean and gives a free
  C-vs-Rust A/B for that test set.

Output:

- one row per program appended to `qemu/results.md`
  (`| program | verdict | wall | notes |`, `notes` is the `test_progs`
  Summary line);
- full run logs in `qemu/logs/<name>.log` and `<name>.restore.log`.

**Resume semantics:** in the no-argument (whole-corpus) form, a program
already present in `qemu/results.md` is skipped, so an interrupted run
resumes by re-invoking the same command. **Explicitly named programs always
re-run**, replacing their existing row. To force a full re-run of the
corpus, move `qemu/results.md` aside first (that file is the only state —
logs are just overwritten). The final table printed by a run lists only the
programs that run actually tested.

**One run at a time.** The driver mutates a single selftests output
directory and rewrites `qemu/results.md` in place; two concurrent runs
corrupt each other's swapped objects, logs and rows. Use separate lanes
(below) for parallelism.

**Timing:** most programs take 10–20s wall; networking-heavy ones
(`test_lwt_ip_encap`, `test_tc_link`, `test_tc_neigh_fib`, `test_uprobe`,
`verifier_mtu`) take 30–160s. Budget a couple of hours for the full
corpus. Per-program caps: 1200s for the make step, 600s
(`QEMU_TIMEOUT`) for a single guest boot.

**Reading the Summary line.** The `notes` column is `test_progs`' own
summary, and its two leading numbers are *not* a ratio
(`test_progs.c`: `printf("Summary: %d/%d PASSED, ...", succ_cnt,
sub_succ_cnt, ...)`) — they are **top-level tests passed / subtests
passed**:

- `1/10 PASSED` — one test, whose 10 subtests all passed;
- `1/0 PASSED` — one test that registers no subtests (normal, not a
  failure);
- `121/2455 PASSED` — 121 tests and 2455 subtests, because the `-t` filter
  expands to every test registered in the consuming `prog_tests` file
  (`verifier_mtu.bpf.o` is consumed by `prog_tests/verifier.c`, which
  registers all 121 `verifier_*` tests). Over-broad relative to the one
  swapped object, which can only catch more regressions, never fewer.

Skips and failures are counted separately; `0 FAILED` is the pass
condition.

**Finding failures:**

```sh
grep -v '| PASS |' qemu/results.md
grep -E "^(#[0-9]+|Summary:)" qemu/logs/<name>.log | tail -20
```

If a program fails, compare with its `.restore.log`: if the **pristine C
object fails the same tests**, the harness or the environment is at fault,
not the translation (see "When the output dir drifts" below).

### Running the corpus in parallel

`qemu-verify.sh` is serial by construction — it mutates one shared
selftests output directory. To use more cores, give each worker its own
worktree and its own copy of that directory:

```sh
scripts/setup-lanes.sh 4      # ../rust-selftests-lane{1..4} + per-lane outputs
```

Then drive `make` directly in each lane (the Makefile takes all paths from
the environment):

```sh
cd ../rust-selftests-lane1
QEMU_CPUS=4 \
  BUILD_DIR=$PWD/../rust-selftests/.build \
  SELFTESTS_OUTPUT=$PWD/../rust-selftests/.build/selftests-output-qemu-lane1 \
  make test-<name> && make restore-<name>
```

The kernel worktree and its BTF are shared read-only; only the selftests
output is per-lane. `setup-lanes.sh` is idempotent. (The lane machinery was
built for the translation sweep — `scripts/lane-sweep.sh`, which drives
`translate.sh` and honours a `sweep/STOP` file for a graceful stop; that
script translates rather than verifies.)

## Running a single test

```sh
make test-<name>      # swap Rust object in, run affected tests
make restore-<name>   # reinstall pristine C object, run them again
```

`make test-<name>` reuses the harness verbatim by construction: the Rust
object is installed as `<name>.bpf.o` in the selftests output and the
kernel's own Makefile regenerates the (possibly signed) skeletons and
relinks `test_progs` from it. The pristine C object is backed up once as
`<name>.bpf.o.corig` on the first swap.

The set of affected tests is discovered from the generated `*.test.d`
dependency files, plus a scan of `prog_tests/*.c` for programs loaded from
disk by name, so program/test name mismatches need no manual mapping. The
resulting file basenames are expanded to the **registered** test names
(`test_<name>()` / `serial_test_<name>()`), because that is what
`test_progs -t` matches.

`scripts/known-bad-tests` lists registered test names that fail with the
**pristine C object** in this harness (kernel limits / environment);
`swap-and-test.sh` subtracts them from the `-t` filter so a bundled
always-broken test cannot fail an otherwise-correct translation.

## Building objects without running tests

```sh
make            # build bld/<name>.bpf.o for every progs/*.rs
make status     # translation coverage vs the kernel progs/
make clean      # drop bld/
```

`make verify` (the standalone verifier gate) runs `uml-veristat` and only
works under `FLAVOR=uml`; it refuses to run otherwise. Under the QEMU
flavor the acceptance gate is `test-<name>` itself.

## When the output dir drifts

The selftests output is mutable state: hundreds of swap/restore cycles can
leave a Rust object behind after a silently failed restore, or let the tree
drift from the sources. Symptom: a test fails for both the Rust object and
the pristine C object. Fix by rebuilding the output from scratch:

```sh
mv .build/selftests-output-qemu{,.drifted}
scripts/build-qemu-selftests.sh
```

Then re-run the affected programs (results for them must be removed from
`qemu/results.md` first, or they will be skipped).

## After changing a pin

`kernel-commit` and `pahole-commit` are the two pins. After changing
either, move `.build/bpf-next`, `.build/selftests-output-qemu` and
`.build/bpftool-output-qemu` aside and re-run
`scripts/build-qemu-kernel.sh` and `scripts/build-qemu-selftests.sh`.
Build the kernel and its modules with the same pahole: module BTF is
deduplicated against the kernel's, and a mismatch shows up as kfunc
argument types that no longer match (see
[history/ci-nightly-results-2026-09-07.md](history/ci-nightly-results-2026-09-07.md)).
`scripts/kernel-gap.sh /path/to/tip` reports what a newer bpf-next would
change for the translations ([kernel-gap.md](kernel-gap.md)).

`make check-kernel-commit` requires the kernel worktree to be the pin plus
exactly the patches in `patches/kernel/`, applied as commits.

## Result files

| file | what |
|---|---|
| `qemu/gate/results.md` | the recorded runtime verdict of every translation; `make ci-nightly` compares its run against this table and never rewrites it |
| `equiv/results/baseline.tsv` | the recorded proof verdict, keyed by object and tool hashes; `equiv/guard.py` re-proves only what changed |
| `nightly/<run>/` | one nightly's report, logs and hashes (not tracked) |
| `qemu/results*.md`, `sweep/`, `docs/history/` | earlier partial runs and dated reports |

`scripts/qemu-gate.sh` re-runs the corpus over parallel lane outputs and
rewrites `qemu/gate/results.md`; back the table up first when running a
subset.

## The UML flavor

`FLAVOR=uml` runs the tests under User Mode Linux instead of QEMU. It is
experimental and not maintained with the rest: it needs a
[uml-veristat](https://github.com/mykola-lysenko/uml-veristat) checkout at
`../uml-harness` (`UML_HARNESS`), a kernel patched by that project, and
an older pin. Nothing else in this repository reads that checkout.
