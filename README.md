# rust-selftests — Rust translations of the kernel BPF selftests

Rust translations of `tools/testing/selftests/bpf/progs/*.c`, compiled
**directly to BPF by upstream rustc/LLVM** (the
[4ast/rust-bpf](https://github.com/4ast/rust-bpf) pipeline — no aya, no
bpf-linker), and validated against the kernel's **unmodified** selftests
harness: the real `prog_tests/*.c`, the real skeleton generation, the real
`test_progs`, running in a guest kernel built from the pinned bpf-next tree
(`kernel-commit`; `make status` and `make ci-local` refuse to run when the
x86 worktree's merge-base with upstream is a different commit).

Current corpus: 596 translated C objects in `progs/`. The recorded
[QEMU gate](qemu/gate/results.md) has 571 PASS / 17 FAIL / 8 NO-ORACLE;
passing consumers can include skipped subtests. See the
[Phase 3 report](docs/phase3-results-2026-09-06.md) for the latest additions
and environment limits. This README is about **running those tests**;
for how a translation is written see `TRANSLATING.md`.

## The two guest flavors

`FLAVOR` selects the oracle the harness runs the tests in:

| FLAVOR | guest | notes |
|---|---|---|
| `qemu` | x86_64 bpf-next at `kernel-commit` + virtme-ng/KVM | **the default** — ~10x faster, real kprobes/uprobes/stack unwinding, test kmods |
| `uml` | UML bpf-next (`uml-harness`) | parked: an older pin with a patched kernel and a reduced feature set; used only when asked for with `FLAVOR=uml` |

Everything below is the QEMU flavor; nothing needs `FLAVOR=` unless UML is
wanted explicitly. The two flavors share `scripts/swap-and-test.sh` and the
Makefile — the flavor only switches the kernel tree, the selftests output
directory and the guest runner.

## Prerequisites for the QEMU flavor

1. **x86_64 kernel worktree** at `../uml-harness/.build/bpf-next-x86` — a
   `git worktree` of bpf-next at `kernel-commit` plus the seven
   selftests/libbpf patches from `uml-harness/patches/bpf-selftests-uml`
   (0004, 0005, 0005b, 0007, 0007b, 0009, 0011), configured to boot under
   virtme-ng (`CONFIG_KVM_GUEST`, `CONFIG_VIRTIO*`, `CONFIG_VIRTIO_FS`,
   `CONFIG_9P_FS`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_BPF_JIT`,
   `CONFIG_KPROBES`, `CONFIG_UPROBES`, `CONFIG_FUNCTION_TRACER`), built to
   `vmlinux` + `arch/x86/boot/bzImage` + `modules`.
2. **virtme-ng** at `~/.local/share/vng-venv/bin/vng` (v1.41 here) and
   access to `/dev/kvm` (be in the `kvm` group).
3. **QEMU selftests output** — build it once with
   `scripts/build-qemu-selftests.sh`. It builds `bpftool` from the x86
   tree into `../uml-harness/.build/bpftool-output-qemu`, `modules` in the
   x86 tree, and then the selftests into
   `../uml-harness/.build/selftests-output-qemu` with the harness-built
   pahole 1.31 on `PATH`, in keep-going mode (a partial `test_progs` is
   expected and fine). After a pin bump: move the old output aside,
   `REBUILD_BPFTOOL=1`, and re-run `scripts/setup-lanes.sh`.
4. **Toolchain for building the Rust objects**: a built
   [4ast/rust-bpf](../rust-bpf) checkout (`bld_deps/` rlibs,
   `bld/bpf-postproc`, `bld/libbtf_macros.so`), LLVM >= 22 at
   `../uml-harness/.build/llvm-install`, and `rustc` (stable is fine;
   needs the `rust-src` component — `RUSTC_BOOTSTRAP=1` is set by the
   Makefile).

Paths default to the `heimdall_experiment` layout; override `KERNEL_SRC`,
`SELFTESTS_OUTPUT`, `VMLINUX_BTF`, `RUSTBPF`, `LLVM_PREFIX` as needed.
Guest sizing/timeouts for the runner: `QEMU_CPUS` (8), `QEMU_MEM` (4G),
`QEMU_TIMEOUT` (600s), `QEMU_KERNEL`, `VNG`.

## Running all the Rust tests in QEMU

```sh
scripts/qemu-verify.sh                      # every progs/*.rs
scripts/qemu-verify.sh fentry_test atomics  # just these
```

`qemu-verify.sh` pins the QEMU flavor's paths itself and for
each program runs, serially:

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
  SELFTESTS_OUTPUT=../uml-harness/.build/selftests-output-qemu-lane1 \
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
mv ../uml-harness/.build/selftests-output-qemu{,.drifted}
scripts/build-qemu-selftests.sh
```

Then re-run the affected programs (results for them must be removed from
`qemu/results.md` first, or they will be skipped).

## Result files

To compare the pinned upstream corpus with a candidate kernel checkout,
run `scripts/kernel-gap.sh /path/to/tip`. The [kernel-gap guide](docs/kernel-gap.md)
describes the report, patch checks, and weekly CI artifacts.

| file | what |
|---|---|
| `qemu/results.md` | 63-program QEMU verification pass (the pre-sweep corpus) |
| `qemu/results-postmerge.md` | 24 programs re-verified on a freshly built output dir after the helper-crate merge |
| `qemu/results-pre-elffix.md` | historical, before the BTF/ELF append fix |
| `sweep/lane-results/lane*.md` | the 4-lane translation sweep: 484 PASS / 117 FAIL of 608 candidates, each verdict from a QEMU test run in its lane |
| `qemu/gate/results.md` | recorded gate on bpf-next 3ccdb078: 571 PASS / 17 FAIL / 8 NO-ORACLE; combines the 2026-09-05 full run with Phase 2 repairs and Phase 3 additions; see `docs/phase3-results-2026-09-06.md` for validation limits |
| `sweep/results.md`, `docs/` | earlier sample sweep and the failure taxonomy |

Translations include documented runtime failures and objects without a
runtime oracle; passing consumers can also skip assertions. Consult the
gate and phase reports for each object's validation status.
`scripts/qemu-gate.sh` re-runs the whole corpus over the four lane outputs
(`qemu/gate/`), which is how a kernel bump is re-validated.
