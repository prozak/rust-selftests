#!/bin/bash
# Phase 3 validation against the pinned C objects. Shared output: run serially.
set -u
cd "$(dirname "$0")/.." || exit 1
trap 'make restore-all >/dev/null' EXIT
trap 'exit 130' INT TERM
names=(fentry_sleepable aggregate_ret_target freplace_ret_pair tracing_struct_int128
       kfunc_implicit_args_tracing ksock_lsm ksock_wq sock_read_xattr
       struct_ops_arena struct_ops_arena_attach test_tc_qevent arena_mem_usage
       arena_kfunc_jit aggregate_ret_func aggregate_ret_kfunc
       aggregate_ret_kfunc_arena arena_kfunc tailcall_callback test_global_percpu_data)
if [ "$#" -gt 0 ]; then names=("$@"); fi
out=qemu/phase3
mkdir -p "$out"
gate_failed=0
for n in "${names[@]}"; do
    make "$PWD/bld/$n.bpf.o" > "$out/$n.build.log" 2>&1 || exit 1
    python3 scripts/translint.py "$n" > "$out/$n.lint.log" 2>&1 || exit 1
done
for n in "${names[@]}"; do
    make restore-all || exit 1
    make "test-$n" > "$out/$n.log" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then gate_failed=1; fi
    make restore-all || exit 1
    c_rc=-
    if [ "$rc" -ne 0 ]; then
        make "restore-$n" > "$out/$n.c.log" 2>&1
        c_rc=$?
        make restore-all || exit 1
    fi
    printf '%s\t%s\t%s\n' "$n" "$rc" "$c_rc" | tee -a "$out/validation.tsv"
done
make restore-all || exit 1
../z3-venv/bin/python equiv/guard.py --jobs 8 "${names[@]}" > "$out/guard.log" 2>&1
rc=$?
tail -25 "$out/guard.log"
if [ "$rc" -ne 0 ]; then exit "$rc"; fi
# Keep environmental failures visible too; the C row explains them, but
# cannot turn a failed Rust runtime run into a passing exit status.
exit "$gate_failed"
