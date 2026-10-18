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

## Running what changed in QEMU

```sh
make gate                        # scripts/gate.py --workers 8
scripts/gate.py fentry_test      # one translation, hash-gated like the rest
scripts/gate.py --all fentry_test   # that one even if unchanged
```

`scripts/gate.py` is the incremental gate: it restores the C objects,
checks the kernel pin, runs `make all`, and compares every translation's
Rust object, C object and gate environment hash with the committed
[`qemu/gate/baseline.tsv`](../qemu/gate/baseline.tsv). Unchanged rows are
skipped; the rest run through their consuming `prog_tests` in QEMU,
`GATE_WORKERS` guests at a time, each over a private overlay of the
selftests output (`scripts/gate-overlay.sh`), the `scripts/gate-serial`
objects afterwards, alone in the shared output. Rows that ran are
rewritten in place (commit them with the translation). Exit 1 means an
alarm: a FAIL (a recorded one keeps alarming until the objects change) or
a PASS that became NO-ORACLE. Logs are `qemu/gate/logs/<name>.log` and
`<name>.c.log` (the C re-run after a FAIL).

Each row records the wall seconds its last run took, and the parallel
queue runs the translations without a record first (new ones) and then
longest first, so a long object cannot land last and hold the makespan.
With the corpus at its 2026-10-17 shape the order is worth about one
percent (the gate is throughput-bound: 776 objects of 27 s on average);
the per-object number is what shows where the time goes.

The environment hash covers the kernel image, the test modules' BTF, the
swap/boot scripts, `known-bad-tests`, `gate-serial` and `QEMU_CPUS` (the
gate uses 4, as the nightly does). When it changes every row is stale and
the gate stops with exit 2 instead of starting a 30-minute full run:
`scripts/gate.py --all` does that run, or `make ci-nightly` followed by
`scripts/gate.py --reseed nightly/<run>/runtime-after.tsv`, which copies
the nightly's verdicts only when its recorded hashes equal the current
ones. The gate holds the nightly's locks, so the two never overlap, and
`make clean-gate-workers` refuses while one runs.

## Running all the Rust tests in QEMU, serially

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
selftests output directory. The parallel driver is the gate:
`scripts/gate.py --all` (`--workers N`, 8 at most) runs every translation
through N guests at once, each over a private overlay of that directory,
and the `scripts/gate-serial` objects alone afterwards; see "Running what
changed in QEMU" above.

### How many workers

Measured 2026-10-16 on a 32-CPU, 23 GB host with 4-CPU, 4 GB guests
(`scripts/gate.py --all <every name>`; the 4-worker full run is the
2026-10-16 nightly's gate stage). Verdicts were identical in every run.

| workers | 63-object subset | full corpus (597) | host RAM peak | load peak |
|---|---|---|---|---|
| 4 | 331 s | 3493 s | 3.7 GB | 9 |
| 8 | 208 s | 2371 s | 7.0 GB | 17 |

The `gate-serial` objects run one at a time at the end whatever the worker
count. When that lane held the 33 `bpf_iter_*` objects as well (about 12
minutes), the parallel part gained 1.6x and the whole gate 1.47x; since
the guest runs `test_progs` from its tmpfs (see `scripts/qemu-test-progs`)
those objects gate in the overlay workers too, the lane is the two
`fentry_recursive*` objects, and the full corpus (605 translations) took
1756 s with eight workers on 2026-10-16. Eight is the default
(`GATE_WORKERS`, `NIGHTLY_GATE_WORKERS`); the guest count is capped at
eight.

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
| `qemu/gate/baseline.tsv` | the recorded runtime verdict, keyed by object and environment hashes; `scripts/gate.py` re-runs only what changed; `make ci-nightly` compares its run against it and never rewrites it |
| `equiv/results/baseline.tsv` | the recorded proof verdict, keyed by object and tool hashes; `equiv/guard.py` re-proves only what changed |
| `nightly/<run>/` | one nightly's report, logs and hashes (not tracked) |
| `qemu/results*.md`, `sweep/`, `docs/history/` | earlier partial runs and dated reports |

## The UML flavor

`FLAVOR=uml` runs the tests under User Mode Linux instead of QEMU. It is
experimental and not maintained with the rest: it needs a
[uml-veristat](https://github.com/mykola-lysenko/uml-veristat) checkout at
`../uml-harness` (`UML_HARNESS`), a kernel patched by that project, and
an older pin. Nothing else in this repository reads that checkout.
