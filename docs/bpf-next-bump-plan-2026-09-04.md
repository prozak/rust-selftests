# Advancing the bpf-next pin: gap analysis and plan (2026-09-04)

## Where we are

| | commit | date |
|---|---|---|
| pinned base (uml-harness `bpf-next-commit`, base of the `bpf-next-x86` worktree) | 520d7d7 | 2026-07-11 |
| bpf-next master today | 3ccdb0781 | 2026-09-04 |

The QEMU flavor kernel is the `qemu-x86` worktree at
`../uml-harness/.build/bpf-next-x86`: the pinned base plus seven
selftests/libbpf patches from `uml-harness/patches/bpf-selftests-uml`
(0004, 0005, 0005b, 0007, 0007b, 0009, 0011). The UML flavor tree
carries the full UML stack on top of the same base.

rust-selftests itself records no kernel commit; it inherits the
harness pin through the worktree. `make status` reports 577 of 975
progs translated against the pinned tree.

## What changed upstream (selftests/bpf, pin -> tip)

Method: `git archive 520d7d7 tools/testing/selftests/bpf` from the
harness tree versus a depth-1 clone of tip, `diff -rq` on `progs/`,
intersected with `progs/*.rs`.

| | count |
|---|---|
| progs/*.c at pin / at tip | 975 / 1008 |
| new .c | 35 |
| removed .c | 1 (`test_lirc_mode2_kern`, renamed to `lirc_mode2`, 16 diff lines) |
| modified .c | 52 |
| modified and already translated | 10 |
| modified and not translated | 42 (almost all `verifier_*` and `*_fail`, i.e. the #25/#27/#32 backlog) |
| prog_tests/*.c changed | 63 |

Harness patch stack against tip (`git apply --check`):

- all seven patches the x86 worktree uses apply cleanly;
- seven UML-only patches conflict (0013, 0013b, 0017, 0020-libbpf,
  0003b, 0009b, 0020-ftrace). Those belong to bpf-uml-selftests and are
  not ours to rebase, so the UML flavor stays on the old pin until that
  project bumps.

### Shared headers and test_loader

- `bpf_misc.h`: new `__skip(reason)` tag (`test_skip=` in
  `test_loader.c`), `__BPF_FEATURE_GOTOL`/`__BPF_FEATURE_ST` feature
  gates, s390 added to the arena-atomics arch list.
- `bpf_experimental.h`: `bpf_sock_read_xattr` kfunc declaration.
- `bpf_tracing_net.h` (2 lines), `task_kfunc_common.h` (14),
  `pyperf.h` (12), new `ksock_common.h`.
- `btf_test_tags.py` rejects unknown tags, so `__skip` must be taught
  before any translation of a test using it can be built.

### The 10 modified translations

| object | diff lines | nature |
|---|---|---|
| stream | 175 (12 tag lines) | new arch-tagged `SEC("syscall")` programs (`__arch_x86_64`/`__arch_arm64`/`__arch_riscv64`/`__arch_loongarch`, `__success __retval(0)`) |
| test_tc_tunnel | 91 | `decap_internal` signature change and body edits |
| rcu_read_lock | 76 | two new programs (`non_own_ref_untrusted_ld`, `rcu_untrusted_union_ld`) |
| fib_lookup | 57 | three new XDP programs plus counters |
| kfunc_call_fail | 39 | two new `?tc` programs (spin-lock unsafe, get_mem zero size) |
| arena_atomics | 18 | arch gate reformatting, s390 added; no code change for x86 |
| kfunc_call_test | 12 | new `kfunc_call_test_spin_lock_safe` program |
| arena_spin_lock | 7 | `qnodes` becomes `__hidden` |
| tracing_failure | 6 | new `?fexit/bpf_testmod_test_int128_ret` program |
| xdp_dummy | 6 | new `__x64_sys_nop` XDP program |

Expect `translint` to flag stream (tags) and every object that gained a
program (program-set mismatch); arena_atomics and arena_spin_lock should
produce byte-identical C objects on x86 and need nothing.

### The 35 new progs

Grouped by where they fall in the existing backlog:

- **Positive non-verifier (#16 shape)**: `aggregate_ret_target`,
  `fentry_sleepable`, `freplace_ret_pair`, `tracing_struct_int128`
  (fexit_bpf2bpf/tracing_struct family), `kfunc_implicit_args_tracing`,
  `ksock_lsm`, `ksock_wq`, `lirc_mode2` (rename of a translated object),
  `sock_read_xattr`, `struct_ops_arena`, `struct_ops_arena_attach`,
  `test_tc_qevent`, `arena_mem_usage`, `arena_kfunc_jit`.
- **Mixed success/failure test_loader objects (#17 mechanism)**:
  `aggregate_ret_func` (6 fail / 7 succ), `aggregate_ret_kfunc` (9/1),
  `aggregate_ret_kfunc_arena` (2/3), `arena_kfunc` (3/6),
  `tailcall_callback` (1/1), `test_global_percpu_data` (2 fail).
- **verifier_* (#25/#27)**: `verifier_aggregate_ret` (7 succ),
  `verifier_zext` (17 succ), `verifier_subprog_insn_stats` (5 succ),
  `verifier_percpu_addr` (2 succ), `verifier_mem_size_reg` (1 succ),
  `verifier_map_lookup_refine` (3 fail), `verifier_ptr_to_buf` (1 fail).
- **Negative non-verifier (#32)**: `bpf_qdisc_fail__untrusted_write`,
  `ksock_lsm_verifier`, `struct_ops_arena_fail`.
- **Not translation targets**: `kasan`, `kasan_harden` (need a KASAN
  kernel config; 19 programs, no tags), `bpf_for_bench` (bench only),
  `veristat_foo`/`veristat_bar` (veristat fixtures, `veristat_bar` has
  no programs).

## Cost of a bump

Every C object changes hash when the selftests are rebuilt against the
new tree, so `equiv/guard.py` re-proves all 577 rows. If
`bld/vmlinux.btf` is present its hash changes too, which the guard
treats as a toolchain change and demands `--all`. That is the same full
re-sweep we already owe for the 361 objects whose stored builds carry
stale `helpers.rs` line info (see rust-selftests 920084c). Doing both in
one rebuild + one re-prove costs the sweep once instead of twice, which
is the main argument for bumping now rather than later.

Rough budget: kernel + modules build tens of minutes, selftests build
about ten, Rust rebuild of 577 objects about fifteen at `-j8`, the
QEMU gate over four lanes an hour or two, the prover sweep several
hours at `-P 8`.

## Plan

### Phase 1: bump the QEMU flavor and re-baseline (infra, one sitting)

1. Pick the target commit. Default: bpf-next master at the time of the
   bump (3ccdb0781 today). Record it in a new `kernel-commit` file in
   rust-selftests and have `make status`/`ci-local` check that
   `git merge-base` of the x86 worktree matches it, so the pin is ours
   and not inherited from the harness.
2. In the isolated harness clone only: fetch bpf-next in
   `.build/bpf-next`, `git checkout --detach <target>` in the
   `bpf-next-x86` worktree (on the `qemu-x86` branch), `git am` the seven
   selftests/libbpf patches (all verified to apply), keep the existing
   `.config` (`make olddefconfig`), rebuild `vmlinux`, `bzImage`,
   `modules`. Do not touch `bpf-next-commit` or the UML tree; that pin
   belongs to bpf-uml-selftests.
3. `scripts/build-qemu-selftests.sh` into a fresh
   `selftests-output-qemu` (move the old one aside as the rollback);
   refresh the lane outputs via `scripts/setup-lanes.sh`.
4. Teach the tag tooling `__skip(reason)` (`test_skip=` prefix in
   `btf_test_tags.py`, `test_tags!`, translint) before rebuilding.
5. Rename `progs/test_lirc_mode2_kern.rs` to `progs/lirc_mode2.rs`;
   carry the baseline row and any sweep/waiver entries.
6. Full Rust rebuild (`FLAVOR=qemu make -j8 -W bpf-rs-core/src/helpers.rs all`,
   or `-B`); this also clears the stale line-info drift.
7. `make restore-all`, `translint`, then the QEMU gate over the four
   lanes for all 577 (old lane sweep). Triage load/attach failures
   first: they are the objects whose kernel-side contract moved.
8. `guard.py --all` at eight jobs. Alarm classes to expect: INEQUIV on
   the ten modified objects until Phase 2 lands; downgrades from EQUIV
   where new kernel BTF changes a kfunc proto the prover models. Reseed
   the baseline from the sweep summary, commit it together with the
   `kernel-commit` file as the bump commit.

### Phase 2: repair the ten modified translations

Order by size, smallest first, each as one commit with `translint`
clean and a `make test-<n>` pass: xdp_dummy, tracing_failure,
arena_spin_lock (verify byte-identical, no edit expected),
arena_atomics (same), kfunc_call_test, kfunc_call_fail, fib_lookup,
rcu_read_lock, test_tc_tunnel, stream. stream needs the `__arch_*`
tags carried through `test_tags!`; check that the tag tooling accepts
them before starting it.

### Phase 3: translate the new positive objects

The 14 positive non-verifier objects above join #16 in the usual wave
style. `lirc_mode2` is done by the rename. `aggregate_ret_*`,
`arena_kfunc`, `tailcall_callback`, `test_global_percpu_data` go
through the #17 decl-tag mechanism because they mix success and
failure programs. The seven `verifier_*` files and the three negative
objects are added to the #25/#27 and #32 counts rather than started
now. kasan, bpf_for_bench and the veristat fixtures are recorded as
non-targets in `make status`.

### Phase 4: keep the gap measurable

Turn the analysis above into `scripts/kernel-gap.sh <tip-checkout>`:
new/removed/modified progs versus `progs/*.rs`, tag-line deltas per
modified translation, header and test_loader diffs, and a
`git apply --check` of the x86 patch set. Run it in `ci-nightly` (#23)
against a weekly depth-1 clone so a bump is a decision with numbers
attached, not an archaeology exercise. Bump cadence: once per bpf-next
merge window, or sooner when a translated object's C source changes.

## Open questions for the bump commit

- ~~Whether to keep the UML flavor at all while its pin diverges from the
  QEMU flavor. The Makefile still defaults `FLAVOR` to uml.~~ Decided
  2026-09-05: the UML branch is parked, kept only as an explicit
  `FLAVOR=uml` opt-in; QEMU is the default everywhere.
- Whether `selftests-output-qemu.drifted` in the harness build dir is
  still needed; it looks like an earlier drift experiment.
