# Stratified sample sweep — results & failure taxonomy (2026-08-01)

60-program stratified sample (35 SEC-kind strata, feature/size spread) from
the 653 eligible untranslated selftest programs; sonnet-5, 2-attempt budget,
30-min timeout, serial UML oracle. Sample/driver: `sweep/sample-2026-08-01.tsv`,
`scripts/sweep.sh`. Per-program rows: `sweep/results.md`; agent logs:
`sweep/logs/` (untracked); failed attempts archived in `sweep/failed/`.

## Headline numbers

| verdict | n | agent cost | wall |
|---|---|---|---|
| PASS | 31 | $60.30 | 3.4 h |
| FAIL | 25 | $81.95 | 6.5 h |
| ORACLE-UNAVAILABLE (pre-gated, free) | 4 | $0 | — |

- **Every one of the 31 passes was a first-attempt pass** (incl. `atomics`,
  re-run after the stdin bug). Corpus grew 11 → 42
  verified translations, adding whole idiom families: struct_ops, freplace,
  fmod_ret, cgroup/cgroup_skb/connect4, arena (+atomics), rbtree/graph kptrs,
  bpf_timer in syscall progs, callback subprogs (for_each_map_elem), LWT encap
  multi-section programs, custom sec handlers, resizable datasec arrays,
  fexit_many_args, tcx links — including `test_cls_redirect` (1,076 loc,
  first-attempt, $5.27).
- **Zero failures are clean model-capability failures.** Every FAIL is
  attributable to a pipeline gap, a harness limitation, or the UML
  environment (classes below). The failure tier nevertheless consumed 58% of
  the spend — pre-filtering these classes is the single biggest cost lever
  for the full sweep.

## Failure taxonomy (25 FAILs)

**A. Pipeline: `add_ksyms.py` emits `void()` FUNC_PROTO for every extern
kfunc/ksym-func — 7** (`kfunc_module_order`, `xfrm_info`, `cgroup_iter_memcg`,
`test_xdp_pull_data`, `iters_task`, `get_func_ip_fsession_test`,
`test_attach_probe`). libbpf's `bpf_core_types_are_compat()` rejects any
kfunc with args/return at load (`func_proto incompatible with vmlinux`). The
DISubroutineType is a hardcoded literal in the script. **Top-priority fix**
(rust-bpf is our clone): emit the real proto from the extern declaration —
rescues all 7 and unlocks the modern kfunc-heavy corpus (open-coded
iterators, kptr/graph APIs, xdp kfuncs).

**B. rustc BTF-emission gaps — 4** (`uptr_map_failure`, `kptr_xchg_inline`,
`test_skeleton`, `metadata_unused`). Missing: `BTF_KIND_TYPE_TAG`
(`__uptr`/`__kptr` member tags), extern-linkage BTF VARs (`__kconfig`
datasec), and a Rust type that reaches BTF as plain `char` (u8/i8 →
"unsigned/signed char"; `prog_tests/metadata.c` needs `char[4]` under
-Werror). Upstream rustc work, same family as the decl_tag gap; long-term.

**C. UML: no CONFIG_KPROBES / CONFIG_UPROBES on arch/um — 4 FAIL + all 4
pre-gated** (`test_overhead`, `test_probe_user`, `test_vmlinux`,
`uprobe_multi_consumers`; pre-gated: `kprobe_multi_empty`,
`kprobe_multi_override`, `test_uprobe`, `dmabuf_iter`). Attach fails
-ENOENT/-EOPNOTSUPP regardless of program content. **QEMU harness resolves
this class** (already queued as next session's first task).

**D. UML: other kernel-config/arch gaps — 2** (`tracing_multi_bench`:
HAVE_SINGLE_FTRACE_DIRECT_OPS; `bpf_iter_netlink`: bundled `task_stack`
subtest = the known stack-unwinding class). Also QEMU-addressable.

**E. Oracle granularity: bundled env-broken subtests fail correct
translations — 3** (`tc_dummy`, `tailcall_cgrp_storage_no_storage`,
`test_spin_lock`). The consuming subtest passes in isolation, but the
test-level `-t` filter drags in unrelated env-broken subtests (uprobe
sleepable etc.). Harness fix: known-bad-subtest deny list (`test_progs -d`)
in swap-and-test.

**F. Harness: test-name discovery mismatch — 2** (`strobemeta_bpf_loop`:
`bpf_verif_scale.c` registers `verif_scale_*` subtests; `xdp_redirect_map`:
`test_xdp_veth.c` registers `xdp_veth_*`). The `-t` filter derives from the
consuming file's basename and matches nothing. Harness fix: map file →
registered test names (`test_progs -l`).

**G. Timeout, undiagnosed — 2** (`test_cls_redirect_subprogs`,
`bpf_iter_task_file`). Killed at the 30-min wall; base `test_cls_redirect`
passed later once the crate had the network helpers, so the wrapper likely
just needs a re-run with a larger budget. Timeouts also lose the cost JSON
(spend under-reported).

**H. Agent/controller verdict divergence — 1** (`verifier_mtu`; also seen on
`test_spin_lock`, counted in E). Agent printed TRANSLATION-OK, controller's
independent gate run failed — bundling and/or flaky serial gates. Rescue
candidates; also an argument for gate-log diffing in the controller.

## Extrapolation to the full 653-program sweep

- Translatable-tier first-attempt rate is effectively 100% in this sample
  (30/30 among programs not blocked by A–F classes), at avg $1.99/program.
- Class A (kfunc protos) is dense in the modern corpus — fix before sweeping
  or forfeit a large fraction.
- Classes C/D/E (~9 FAILs + 4 pre-gates here, plus the stack-trace exclusion
  class) convert to testable under a QEMU harness; combined with A fixed, a
  realistic full-sweep pass-tier is several hundred programs.
- Infrastructure before scaling: parallel lanes (per-lane worktree + own
  selftests-output + own bld/, helper additions merged between batches),
  larger timeout tier for >400-loc programs, cost capture on timeout kill.

## Corrections applied during the run

- `bench.sh`-inherited stdin bug in the sweep loop: `claude` consumed a
  sample line (`atomics` was silently skipped; re-run after the fix).
- sweep.sh originally restored only PASSed programs; FAILed programs' last
  Rust attempts stayed installed in the selftests output and broke
  freplace-class restore validations (target-object cross-dependencies).
  All 25 were restored post-run; failed attempts archived to `sweep/failed/`.
