# bpf-next bump 3ccdb078 → 645f5fcf: gap analysis and plan (2026-10-16)

The second pin bump. Method as in
[bpf-next-bump-plan-2026-09-04.md](bpf-next-bump-plan-2026-09-04.md):
`scripts/kernel-gap.sh` over a depth-1 clone of bpf-next master, Phase 1
rebuilds and re-baselines the whole corpus on the new pin, Phase 2 repairs
the translations whose C source changed, one commit per object.

Base: `3ccdb07813829ba9487273e75d1cb238cfa774c1` (2026-09-04).
Candidate: `645f5fcf7a5582f5d6ed2322f41cb34076c63b2c` (bpf-next master as of
2026-10-16, "Merge branch
'bpf-follow-up-by-value-struct-and-__int128-argument-support'").

## Drift

| | |
|---|---|
| `progs/*.c` objects | 1008 → 1065 |
| added | 57 (5 of them non-targets: `bpf_for_bench`, `kasan`, `kasan_harden`, `veristat_bar`, `veristat_foo`) |
| removed / renamed | 0 |
| modified | 113, of which **32 translated** |
| C test consumers changed | 87 |
| shared headers changed | 16 |

All 637 translations still exist at the candidate.

### Shared contracts

- `progs/bpf_misc.h` gained `__msg_next`, `__msg_next_unpriv`,
  `__prepare_priv`, `__load_if_large_stack`, `__load_if_no_large_stack`
  (`test_expect_msg_next=`, `test_expect_msg_next_unpriv=`,
  `test_prepare_priv`, `stack_mode=large|small`); `test_loader.c` also
  accepts `BPF_F_ARENA_SCALAR` in `__flag`. `scripts/btf_test_tags.py`
  mirrors the five new attributes (the flag is a plain macro-name payload
  and needed nothing).
- `test_loader.c`: programs now run in `stack_mode` large/small according
  to the JIT's >512-byte stack support; `__caps_unpriv` keeps the named
  capabilities through `drop_capabilities`; `bpf_program__add_flags`.
- `test_kmods/bpf_testmod_kfunc.h`: by-value struct and `__int128` kfunc
  arguments (`bpf_kfunc_call_test_pair_arg*`, `*_i128_arg*`,
  `bpf_kfunc_call_test_ptr_arg`, `bpf_kfunc_call_test_pair_arena_arg`) and
  the `__uninit` out-parameter kfuncs; `bpf_testmod.h` gained the
  `test_trampoline_stack_args` struct_ops member.
- `bpf_kfuncs.h`: `bpf_inode_init_xattr`. `bpf_tracing_net.h`: `TCPHDR_FIN`.
- `tools/testing/selftests/bpf/config` now asks for
  `CONFIG_DEBUG_INFO_BTF_INLINE=y`, which depends on `PAHOLE_HAS_INLINE`
  (`PAHOLE_VERSION >= 132`). The pinned pahole was a 2026-08-08 master
  commit reporting v1.31, so the bump also moves `pahole-commit` to the
  v1.32 release (`fa725d687ce3a712ef296b46bc63ea57ef466014`, 2026-09-12,
  which contains the old pin's int128 argument fix; master is five arm64
  and libbpf-sync commits past it) and adds the option to
  `kernel/config-x86_64`. Its consumer is the new `prog_tests/btf_inline.c`
  (reads `/sys/kernel/btf/bpf_testmod.inline`), which loads no BPF object.

## Phase 1: the bump

1. Rollbacks: `.build/bpf-next`, `.build/selftests-output-qemu` and
   `.build/bpftool-output-qemu` moved to `*.pin-3ccdb078`;
   `bld/vmlinux.btf.pin-3ccdb078`; the old pahole stays in
   `.build/pahole-416753b4ba90fe3b72952ace9954edb321657936/`.
2. `kernel-commit` = `645f5fcf7a5582f5d6ed2322f41cb34076c63b2c`,
   `pahole-commit` = v1.32; `scripts/build-qemu-kernel.sh` (fresh depth-1
   clone, `olddefconfig` on `kernel/config-x86_64`, vmlinux/bzImage/modules
   with the pinned pahole), then `scripts/build-qemu-selftests.sh`.
3. Forced corpus rebuild (`bld/vmlinux.btf` and every `.keep` change with
   the kernel), `make restore-all`, `scripts/translint.py`: the expected
   noise is the program-set errors of the 32 objects below; anything else
   is new information.
4. `equiv/guard.py --all --jobs 8`, then `scripts/gate.py --all` (never
   both at once), then `make ci-nightly`; reseed both baselines from the
   nightly, update the README status, commit the bump.

## Phase 2: the 32 modified translations

Smallest first. "New programs" are the `SEC(...)` definitions the C object
gained; an object with none changed only bodies, strings or tags.

| # | Object | C lines + / − | New programs | Tag lines + / − |
|---|---|---|---|---|
| 1 | `test_skc_to_unix_sock` | 1 / 1 | — | 0 / 0 |
| 2 | `stack_arg` | 2 / 1 | — | 0 / 0 |
| 3 | `stack_arg_kfunc` | 2 / 1 | — | 0 / 0 |
| 4 | `bpf_iter_netlink` | 2 / 2 | — | 0 / 0 |
| 5 | `bpf_iter_udp4` | 2 / 2 | — | 0 / 0 |
| 6 | `bpf_iter_udp6` | 2 / 2 | — | 0 / 0 |
| 7 | `test_snprintf` | 2 / 2 | — | 0 / 0 |
| 8 | `lsm` | 4 / 1 | — | 0 / 0 |
| 9 | `rcu_read_lock` | 3 / 3 | — | 0 / 0 |
| 10 | `bpf_iter_unix` | 3 / 4 | — | 0 / 0 |
| 11 | `test_bpf_nf` | 4 / 4 | — | 0 / 0 |
| 12 | `test_tc_link` | 10 / 0 | — | 0 / 0 |
| 13 | `bpf_iter_tcp4` | 5 / 6 | — | 0 / 0 |
| 14 | `bpf_iter_tcp6` | 5 / 6 | — | 0 / 0 |
| 15 | `tailcall_callback` | 16 / 0 | `tailcall_callback_3` | 1 / 0 |
| 16 | `arena_kfunc` | 16 / 1 | `arena_arg_stack_after_pair` | 3 / 1 |
| 17 | `stream` | 20 / 0 | `stream_nmi`, `?` | 1 / 0 |
| 18 | `sock_destroy_prog` | 30 / 0 | `iter_tcp6_timewait` | 0 / 0 |
| 19 | `tracing_struct_int128` | 45 / 0 | `test_int128_stack_fentry`, `test_int128_stack_fexit`, `test_int128_backfill_fentry`, `test_int128_backfill_fexit` | 0 / 0 |
| 20 | `struct_ops_private_stack_fail` | 44 / 3 | — | 0 / 0 |
| 21 | `timer` | 59 / 1 | `test_loop_rearm` | 0 / 0 |
| 22 | `refcounted_kptr` | 61 / 0 | `refcount_acquire_owning_input_no_null_check`, `refcount_acquire_rcu_map_kptr_null_checked` | 2 / 0 |
| 23 | `test_global_func1` | 65 / 0 | `global_func1_deep` | 2 / 0 |
| 24 | `test_spin_lock_fail` | 65 / 2 | `callback_value_lock_identity`, `callback_inner_map_value_lock_identity` | 0 / 0 |
| 25 | `timer_mim_reject` | 83 / 1 | `?`, `callback_map_uid_mismatch`, `callback_map_uid_match` | 0 / 0 |
| 26 | `ksock_wq` | 75 / 13 | — | 0 / 0 |
| 27 | `rbtree_fail` | 86 / 2 | `rbtree_api_add_bad_cb_res_spin_unlock`, `rbtree_api_add_bad_cb_subprog_unlock`, `rbtree_api_add_cb_subprog_allowed` | 5 / 2 |
| 28 | `verifier_mtu` | 88 / 0 | `tc_writeonly_mtu`, `tc_readwrite_mtu`, `xdp_writeonly_mtu`, `tc_readonly_mtu`, `tc_writeonly_output` | 5 / 0 |
| 29 | `rhash` | 112 / 0 | `test_rhash_kptr_update`, `test_rhash_kptr_delete` | 0 / 0 |
| 30 | `file_reader` | 129 / 0 | `on_open_non_sleepable_first`, `on_open_sleepable_first` | 0 / 0 |
| 31 | `refcounted_kptr_fail` | 151 / 2 | `refcount_acquire_rcu_map_kptr_unchecked_drop`, `rbtree_remove_after_rcu_unlock`, `refcount_acquire_after_rcu_unlock`, `graph_kptr_after_spin_unlock` | 7 / 2 |
| 32 | `arena_atomics` | 173 / 38 | `fetch_r0` | 0 / 0 |

Notes from the diffs:

- `bpf_iter_{netlink,tcp4,tcp6,udp4,udp6,unix}`, `test_snprintf`: `%pK`
  left `BPF_SEQ_PRINTF`/`BPF_SNPRINTF`; the format strings print a literal
  `0` now. String-only changes, but the prover compares the strings.
- `test_skc_to_unix_sock`, `bpf_iter_unix`: the bound is
  `sizeof(sun_path)` (108) instead of `sizeof(struct sockaddr_un)` (110).
- `stack_arg*`: riscv arch gate only; `rcu_read_lock`: comment only.
- `tracing_struct_int128`: four programs reading `__int128` stack
  arguments (`bpf_testmod_test_int128_stack/_backfill`); the 2026-09 bump
  found pahole 1.31 dropping the int128 testmod function from BTF
  (`tracing-environment-2026-09-07.md`), check the module BTF first.
- `struct_ops_private_stack_fail`, `test_global_func1`: deep 480-byte
  subprog chains for the large-stack JIT budget; `__load_if_no_large_stack`.
- `arena_kfunc`: `arena_arg_stack_after_pair` is `#if defined(__clang__)`
  and uses the by-value `prog_test_pair_arg` kfunc — by-value struct
  arguments in Rust `extern "C"` need the same two-register lowering.
- `arena_atomics`: the biggest diff (+173/−38), a `fetch_r0` program and
  reworked atomics; read the whole diff, not the hunks.
- `ksock_wq`: ksock kfuncs renamed/reshaped (`bpf_ksock_*`).
- `file_reader`: `bpf_dynptr_from_file`/`bpf_dynptr_file_discard`,
  `bpf_task_work_schedule_signal` in two new `lsm/file_open` programs.
- `rbtree_fail`, `refcounted_kptr*`, `test_spin_lock_fail`,
  `timer_mim_reject`: new negative programs; tags copied verbatim through
  `test_tags!`, including the `{{regex}}` ones.
- `verifier_mtu`: five programs on read-only/write-only maps
  (`read from map forbidden`).

## Results

### Harness

The selftests Makefile is split into `Makefile.buildvars`, `Makefile.skel`
and `Makefile.runner` at 645f5fcf; the test objects are compiled by a
runner sub-make that the main Makefile's `test_progs` rule always runs
(`FORCE`), and `<name>.test.o` is no longer a goal the main Makefile
knows. The first `gate.py --all` failed every object at the swap
(`No rule to make target '.../<name>.test.o'`); `scripts/swap-and-test.sh`
now asks for `test_progs` only and checks that each consuming test object
came out newer than the regenerated skeleton (PERMISSIVE mode drops a
failed compile from the link silently). The skeleton goals
(`<name>.skel.h`, double slash) still work.

### Proof (`equiv/guard.py --all --jobs 8`, 21 min)

| | 2026-10-16 before (c7d8ae1) | after the bump |
|---|---|---|
| EQUIV | 449 | 440 |
| BAIL | 123 | 123 |
| TIMEOUT | 38 | 38 |
| UNKNOWN | 13 | 18 |
| NOPROGS | 13 | 13 |
| INEQUIV | 1 | 4 |
| ERROR | 0 | 1 |

625 of 637 objects keep their verdict. 633 of the 637 Rust objects are
byte-identical to the ones built on the old pin (the kernel BTF the
pipeline reads only feeds kfunc/ksym resolution and type ids: the four
that changed are `bpf_iter_task_btf` and `netif_receive_skb`, whose
`type_id.py` ids follow the kernel BTF, `ksock_wq`, whose kfunc
prototypes come from the module BTF, and `bpf_iter_tcp6`), while 587
of the 637 C objects changed (new `vmlinux.h`, headers and sources). The
twelve verdict changes:

- INEQUIV, all three with a changed C source: `arena_atomics`
  (`raw_tp/sys_enter:and`, the and32/and64 results and the noreturn
  values differ: the C rewrote its atomics), `struct_ops_private_stack_fail`
  (`struct_ops:test_2`, `val_j` now adds the deep subprog chain),
  `test_tc_link` (`tc/egress:tc8`, which now parses the IP header and
  returns early on non-ICMP). `cpumask_success` keeps its pre-existing
  INEQUIV (the bool-return case, README).
- EQUIV → UNKNOWN on UNPAIRED programs the translations do not define yet:
  `sock_destroy_prog`, `tailcall_callback`, `test_global_func1`,
  `timer_mim_reject`, `tracing_struct_int128`, `verifier_mtu`.
- `bpf_iter_unix` BAIL → TIMEOUT (its C changed too; the one program was
  never proved).
- `test_tcp_hdr_options` UNKNOWN → BAIL ("symbolic size argument in
  sockops@624"): C source unchanged, both objects rebuilt against the new
  kernel BTF.
- `test_urandom_usdt` TIMEOUT → ERROR: the prover died with
  `RecursionError: maximum recursion depth exceeded` inside a z3 ctypes
  call instead of hitting its 180 s limit. A prover robustness issue, not a
  translation one; the row was a TIMEOUT before.

### Runtime (`scripts/gate.py --all --workers 8`, 28 min)

| | before (c7d8ae1) | after the bump |
|---|---|---|
| PASS | 627 | 610 |
| FAIL | 0 | 17 |
| NO-ORACLE | 10 | 10 |

The 17 FAIL rows are all objects whose C source changed, and the C object
passes in every case (`C-PASS`): `arena_atomics`, `arena_kfunc`,
`file_reader`, `ksock_wq`, `lsm`, `rbtree_fail`, `refcounted_kptr_fail`,
`rhash`, `sock_destroy_prog`, `stream`, `struct_ops_private_stack_fail`,
`test_global_func1`, `test_snprintf`, `test_spin_lock_fail`, `timer`,
`timer_mim_reject`, `tracing_struct_int128`. No row outside the drift set
changed, and `known-bad-tests` needed no addition.

`scripts/translint.py`: 41 errors in 16 of the 32 drift objects (gained
programs, changed `__msg` texts, new `private(...)` sections), nothing
elsewhere. `make ci-local` stays red on translint, the guard's INEQUIV rows
and the gate's FAIL rows until Phase 2 lands.
