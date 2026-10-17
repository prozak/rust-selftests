// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_ctx.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_ctx.rs
// (include!d below): syscall_ctx_fixed_off_write, syscall_ctx_fixed_off_read, syscall_ctx_unaligned_fixed_off_read, syscall_ctx_unaligned_fixed_off_write, syscall_ctx_var_off_read, syscall_ctx_var_off_write, syscall_ctx_unaligned_var_off_read, syscall_ctx_unaligned_var_off_write, syscall_ctx_u16_max_fixed_off, syscall_ctx_u16_max_var_off, syscall_ctx_neg_var_off, syscall_ctx_unbounded_var_off, syscall_ctx_helper_fixed_off_read, syscall_ctx_helper_fixed_off_write, syscall_ctx_helper_unaligned_fixed_off_read, syscall_ctx_helper_unaligned_fixed_off_write, syscall_ctx_helper_var_off_read, syscall_ctx_helper_var_off_write, syscall_ctx_helper_unaligned_var_off_read, syscall_ctx_helper_unaligned_var_off_write, syscall_ctx_helper_u16_max_fixed_off_read, syscall_ctx_helper_u16_max_fixed_off_write, syscall_ctx_helper_u16_max_var_off_read, syscall_ctx_helper_u16_max_var_off_write, syscall_ctx_helper_zero_sized_read, syscall_ctx_helper_zero_sized_write, syscall_ctx_kfunc_fixed_off, syscall_ctx_kfunc_var_off, syscall_ctx_kfunc_unaligned_fixed_off, syscall_ctx_kfunc_unaligned_var_off, syscall_ctx_kfunc_u16_max_fixed_off, syscall_ctx_kfunc_u16_max_var_off, syscall_ctx_kfunc_zero_sized, no_rewrite_kprobe_fixed, no_rewrite_kprobe_var, no_rewrite_kprobe_neg, no_rewrite_kprobe_helper_read_fixed, no_rewrite_kprobe_helper_write_fixed, no_rewrite_kprobe_helper_read_var, no_rewrite_kprobe_helper_write_var, no_rewrite_kprobe_helper_read_zero, no_rewrite_kprobe_helper_write_zero, no_rewrite_kprobe_kfunc_fixed, no_rewrite_kprobe_kfunc_var, no_rewrite_kprobe_kfunc_zero, no_rewrite_tp_fixed, no_rewrite_tp_var, no_rewrite_tp_neg, no_rewrite_tp_helper_read_fixed, no_rewrite_tp_helper_write_fixed, no_rewrite_tp_helper_read_var, no_rewrite_tp_helper_write_var, no_rewrite_tp_helper_read_zero, no_rewrite_tp_helper_write_zero, no_rewrite_tp_kfunc_fixed, no_rewrite_tp_kfunc_var, no_rewrite_tp_kfunc_zero, no_rewrite_raw_tp_fixed, no_rewrite_raw_tp_var, no_rewrite_raw_tp_neg, no_rewrite_raw_tp_helper_read_fixed, no_rewrite_raw_tp_helper_write_fixed, no_rewrite_raw_tp_helper_read_var, no_rewrite_raw_tp_helper_write_var, no_rewrite_raw_tp_helper_read_zero, no_rewrite_raw_tp_helper_write_zero, no_rewrite_raw_tp_kfunc_fixed, no_rewrite_raw_tp_kfunc_var, no_rewrite_raw_tp_kfunc_zero, no_rewrite_raw_tp_w_fixed, no_rewrite_raw_tp_w_var, no_rewrite_raw_tp_w_neg, no_rewrite_raw_tp_w_helper_read_fixed, no_rewrite_raw_tp_w_helper_write_fixed, no_rewrite_raw_tp_w_helper_read_var, no_rewrite_raw_tp_w_helper_write_var, no_rewrite_raw_tp_w_helper_read_zero, no_rewrite_raw_tp_w_helper_write_zero, no_rewrite_raw_tp_w_kfunc_fixed, no_rewrite_raw_tp_w_kfunc_var, no_rewrite_raw_tp_w_kfunc_zero, no_rewrite_fentry_fixed, no_rewrite_fentry_var, no_rewrite_fentry_neg, no_rewrite_fentry_helper_read_fixed, no_rewrite_fentry_helper_write_fixed, no_rewrite_fentry_helper_read_var, no_rewrite_fentry_helper_write_var, no_rewrite_fentry_helper_read_zero, no_rewrite_fentry_helper_write_zero, no_rewrite_fentry_kfunc_fixed, no_rewrite_fentry_kfunc_var, no_rewrite_fentry_kfunc_zero, no_rewrite_cgroup_dev_fixed, no_rewrite_cgroup_dev_var, no_rewrite_cgroup_dev_neg, no_rewrite_cgroup_dev_helper_read_fixed, no_rewrite_cgroup_dev_helper_write_fixed, no_rewrite_cgroup_dev_helper_read_var, no_rewrite_cgroup_dev_helper_write_var, no_rewrite_cgroup_dev_helper_read_zero, no_rewrite_cgroup_dev_helper_write_zero, no_rewrite_cgroup_dev_kfunc_fixed, no_rewrite_cgroup_dev_kfunc_var, no_rewrite_cgroup_dev_kfunc_zero, no_rewrite_netfilter_fixed, no_rewrite_netfilter_var, no_rewrite_netfilter_neg, no_rewrite_netfilter_helper_read_fixed, no_rewrite_netfilter_helper_write_fixed, no_rewrite_netfilter_helper_read_var, no_rewrite_netfilter_helper_write_var, no_rewrite_netfilter_helper_read_zero, no_rewrite_netfilter_helper_write_zero, no_rewrite_netfilter_kfunc_fixed, no_rewrite_netfilter_kfunc_var, no_rewrite_netfilter_kfunc_zero.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_ctx` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: context_stores_via_bpf_atomic make_ptr_to_ctx_unusable unmodified_ctx_pointer_to_helper ctx_pointer_to_helper_1 ctx_pointer_to_helper_2 ctx_pointer_to_helper_3 or_null_check_1_ctx or_null_check_2_null or_null_check_3_1 null_check_4_ctx_const null_check_5_null_connect null_check_6_null_bind null_check_7_ctx_bind null_check_8_null_bind invalid_narrow_loadbpf_sockoptsk invalid_narrow_loadbpf_sockoptoptval invalid_narrow_loadbpf_sockoptoptval_end invalid_narrow_load__sk_buffsk invalid_narrow_loadbpf_sock_addrsk invalid_narrow_loadbpf_sock_opssk invalid_narrow_loadbpf_sock_opsskb_data invalid_narrow_loadbpf_sock_opsskb_data_end invalid_narrow_loadbpf_sock_opsskb_hwtstamp unaligned_ctx_access___sk_buffdata unaligned_ctx_access_bpf_nf_ctxskb padding_ctx_access_bpf_sock_addr padding_ctx_access_bpf_sk_lookup padding_ctx_access___sk_buff padding_ctx_access_bpf_sock padding_ctx_access_sk_reuseport_md syscall_ctx_fixed_off_write syscall_ctx_fixed_off_read syscall_ctx_unaligned_fixed_off_read syscall_ctx_unaligned_fixed_off_write syscall_ctx_var_off_read syscall_ctx_var_off_write syscall_ctx_unaligned_var_off_read syscall_ctx_unaligned_var_off_write syscall_ctx_u16_max_fixed_off syscall_ctx_u16_max_var_off syscall_ctx_neg_var_off syscall_ctx_unbounded_var_off syscall_ctx_helper_fixed_off_read syscall_ctx_helper_fixed_off_write syscall_ctx_helper_unaligned_fixed_off_read syscall_ctx_helper_unaligned_fixed_off_write syscall_ctx_helper_var_off_read syscall_ctx_helper_var_off_write syscall_ctx_helper_unaligned_var_off_read syscall_ctx_helper_unaligned_var_off_write syscall_ctx_helper_u16_max_fixed_off_read syscall_ctx_helper_u16_max_fixed_off_write syscall_ctx_helper_u16_max_var_off_read syscall_ctx_helper_u16_max_var_off_write syscall_ctx_helper_zero_sized_read syscall_ctx_helper_zero_sized_write syscall_ctx_kfunc_fixed_off syscall_ctx_kfunc_var_off syscall_ctx_kfunc_unaligned_fixed_off syscall_ctx_kfunc_unaligned_var_off syscall_ctx_kfunc_u16_max_fixed_off syscall_ctx_kfunc_u16_max_var_off syscall_ctx_kfunc_zero_sized no_rewrite_kprobe_fixed no_rewrite_kprobe_var no_rewrite_kprobe_neg no_rewrite_kprobe_helper_read_fixed no_rewrite_kprobe_helper_write_fixed no_rewrite_kprobe_helper_read_var no_rewrite_kprobe_helper_write_var no_rewrite_kprobe_helper_read_zero no_rewrite_kprobe_helper_write_zero no_rewrite_kprobe_kfunc_fixed no_rewrite_kprobe_kfunc_var no_rewrite_kprobe_kfunc_zero no_rewrite_tp_fixed no_rewrite_tp_var no_rewrite_tp_neg no_rewrite_tp_helper_read_fixed no_rewrite_tp_helper_write_fixed no_rewrite_tp_helper_read_var no_rewrite_tp_helper_write_var no_rewrite_tp_helper_read_zero no_rewrite_tp_helper_write_zero no_rewrite_tp_kfunc_fixed no_rewrite_tp_kfunc_var no_rewrite_tp_kfunc_zero no_rewrite_raw_tp_fixed no_rewrite_raw_tp_var no_rewrite_raw_tp_neg no_rewrite_raw_tp_helper_read_fixed no_rewrite_raw_tp_helper_write_fixed no_rewrite_raw_tp_helper_read_var no_rewrite_raw_tp_helper_write_var no_rewrite_raw_tp_helper_read_zero no_rewrite_raw_tp_helper_write_zero no_rewrite_raw_tp_kfunc_fixed no_rewrite_raw_tp_kfunc_var no_rewrite_raw_tp_kfunc_zero no_rewrite_raw_tp_w_fixed no_rewrite_raw_tp_w_var no_rewrite_raw_tp_w_neg no_rewrite_raw_tp_w_helper_read_fixed no_rewrite_raw_tp_w_helper_write_fixed no_rewrite_raw_tp_w_helper_read_var no_rewrite_raw_tp_w_helper_write_var no_rewrite_raw_tp_w_helper_read_zero no_rewrite_raw_tp_w_helper_write_zero no_rewrite_raw_tp_w_kfunc_fixed no_rewrite_raw_tp_w_kfunc_var no_rewrite_raw_tp_w_kfunc_zero no_rewrite_fentry_fixed no_rewrite_fentry_var no_rewrite_fentry_neg no_rewrite_fentry_helper_read_fixed no_rewrite_fentry_helper_write_fixed no_rewrite_fentry_helper_read_var no_rewrite_fentry_helper_write_var no_rewrite_fentry_helper_read_zero no_rewrite_fentry_helper_write_zero no_rewrite_fentry_kfunc_fixed no_rewrite_fentry_kfunc_var no_rewrite_fentry_kfunc_zero no_rewrite_cgroup_dev_fixed no_rewrite_cgroup_dev_var no_rewrite_cgroup_dev_neg no_rewrite_cgroup_dev_helper_read_fixed no_rewrite_cgroup_dev_helper_write_fixed no_rewrite_cgroup_dev_helper_read_var no_rewrite_cgroup_dev_helper_write_var no_rewrite_cgroup_dev_helper_read_zero no_rewrite_cgroup_dev_helper_write_zero no_rewrite_cgroup_dev_kfunc_fixed no_rewrite_cgroup_dev_kfunc_var no_rewrite_cgroup_dev_kfunc_zero no_rewrite_netfilter_fixed no_rewrite_netfilter_var no_rewrite_netfilter_neg no_rewrite_netfilter_helper_read_fixed no_rewrite_netfilter_helper_write_fixed no_rewrite_netfilter_helper_read_var no_rewrite_netfilter_helper_write_var no_rewrite_netfilter_helper_read_zero no_rewrite_netfilter_helper_write_zero no_rewrite_netfilter_kfunc_fixed no_rewrite_netfilter_kfunc_var no_rewrite_netfilter_kfunc_zero

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    context_stores_via_bpf_atomic:
        __description("context stores via BPF_ATOMIC"),
        __failure,
        __msg("BPF_ATOMIC stores into R1 ctx is not allowed");
    make_ptr_to_ctx_unusable:
        __description("arithmetic ops make PTR_TO_CTX unusable"),
        __failure,
        __msg("dereference of modified ctx ptr");
    unmodified_ctx_pointer_to_helper:
        __description("pass unmodified ctx pointer to helper"),
        __success,
        __retval("0");
    ctx_pointer_to_helper_1:
        __description("pass modified ctx pointer to helper, 1"),
        __failure,
        __msg("negative offset ctx ptr R1 off=-612 disallowed");
    ctx_pointer_to_helper_2:
        __description("pass modified ctx pointer to helper, 2"),
        __failure,
        __msg("negative offset ctx ptr R1 off=-612 disallowed");
    ctx_pointer_to_helper_3:
        __description("pass modified ctx pointer to helper, 3"),
        __failure,
        __msg("variable ctx access var_off=(0x0; 0x4)");
    or_null_check_1_ctx:
        __description("pass ctx or null check, 1: ctx"),
        __success;
    or_null_check_2_null:
        __description("pass ctx or null check, 2: null"),
        __success;
    or_null_check_3_1:
        __description("pass ctx or null check, 3: 1"),
        __failure,
        __msg("R1 type=scalar expected=ctx");
    null_check_4_ctx_const:
        __description("pass ctx or null check, 4: ctx - const"),
        __failure,
        __msg("negative offset ctx ptr R1 off=-612 disallowed");
    null_check_5_null_connect:
        __description("pass ctx or null check, 5: null (connect)"),
        __success;
    null_check_6_null_bind:
        __description("pass ctx or null check, 6: null (bind)"),
        __success;
    null_check_7_ctx_bind:
        __description("pass ctx or null check, 7: ctx (bind)"),
        __success;
    null_check_8_null_bind:
        __description("pass ctx or null check, 8: null (bind)"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    invalid_narrow_loadbpf_sockoptsk:
        __description("narrow load on field sk of bpf_sockopt"),
        __failure,
        __msg("invalid bpf_context access");
    invalid_narrow_loadbpf_sockoptoptval:
        __description("narrow load on field optval of bpf_sockopt"),
        __failure,
        __msg("invalid bpf_context access");
    invalid_narrow_loadbpf_sockoptoptval_end:
        __description("narrow load on field optval_end of bpf_sockopt"),
        __failure,
        __msg("invalid bpf_context access");
    invalid_narrow_load__sk_buffsk:
        __description("narrow load on field sk of __sk_buff"),
        __failure,
        __msg("invalid bpf_context access");
    invalid_narrow_loadbpf_sock_addrsk:
        __description("narrow load on field sk of bpf_sock_addr"),
        __failure,
        __msg("invalid bpf_context access");
    invalid_narrow_loadbpf_sock_opssk:
        __description("narrow load on field sk of bpf_sock_ops"),
        __failure,
        __msg("invalid bpf_context access");
    invalid_narrow_loadbpf_sock_opsskb_data:
        __description("narrow load on field skb_data of bpf_sock_ops"),
        __failure,
        __msg("invalid bpf_context access");
    invalid_narrow_loadbpf_sock_opsskb_data_end:
        __description("narrow load on field skb_data_end of bpf_sock_ops"),
        __failure,
        __msg("invalid bpf_context access");
    invalid_narrow_loadbpf_sock_opsskb_hwtstamp:
        __description("narrow load on field skb_hwtstamp of bpf_sock_ops"),
        __failure,
        __msg("invalid bpf_context access");
    unaligned_ctx_access___sk_buffdata:
        __description("unaligned access on field data of __sk_buff"),
        __failure,
        __msg("invalid bpf_context access");
    unaligned_ctx_access_bpf_nf_ctxskb:
        __description("unaligned access on field skb of bpf_nf_ctx"),
        __failure,
        __msg("invalid bpf_context access");
    padding_ctx_access_bpf_sock_addr:
        __failure,
        __msg("invalid bpf_context access"),
        __description("access on bpf_sock_addr padding after msg_src_ip6[3]");
    padding_ctx_access_bpf_sk_lookup:
        __success,
        __description("access on bpf_sk_lookup padding after remote_port");
    padding_ctx_access___sk_buff:
        __failure,
        __msg("invalid bpf_context access"),
        __description("access on __sk_buff padding after tstamp_type");
    padding_ctx_access_bpf_sock:
        __failure,
        __msg("invalid bpf_context access"),
        __description("access on bpf_sock padding after dst_port");
    padding_ctx_access_sk_reuseport_md:
        __failure,
        __msg("invalid bpf_context access"),
        __description("access on sk_reuseport_md padding after hash");
    syscall_ctx_fixed_off_write:
        __description("syscall: write to ctx with fixed offset"),
        __success;
    syscall_ctx_fixed_off_read:
        __description("syscall: read ctx with fixed offset"),
        __success;
    syscall_ctx_unaligned_fixed_off_read:
        __description("syscall: unaligned read ctx with fixed offset"),
        __success;
    syscall_ctx_unaligned_fixed_off_write:
        __description("syscall: unaligned write ctx with fixed offset"),
        __success;
    syscall_ctx_var_off_read:
        __description("syscall: read ctx with variable offset"),
        __success;
    syscall_ctx_var_off_write:
        __description("syscall: write ctx with variable offset"),
        __success;
    syscall_ctx_unaligned_var_off_read:
        __description("syscall: unaligned read ctx with variable offset"),
        __success;
    syscall_ctx_unaligned_var_off_write:
        __description("syscall: unaligned write ctx with variable offset"),
        __success;
    syscall_ctx_u16_max_fixed_off:
        __description("syscall: reject ctx access past U16_MAX with fixed offset"),
        __failure,
        __msg("outside of the allowed memory range");
    syscall_ctx_u16_max_var_off:
        __description("syscall: reject ctx access past U16_MAX with variable offset"),
        __failure,
        __msg("outside of the allowed memory range");
    syscall_ctx_neg_var_off:
        __description("syscall: reject negative variable offset ctx access"),
        __failure,
        __msg("min value is negative");
    syscall_ctx_unbounded_var_off:
        __description("syscall: reject unbounded variable offset ctx access"),
        __failure,
        __msg("unbounded memory access");
    syscall_ctx_helper_fixed_off_read:
        __description("syscall: helper read ctx with fixed offset"),
        __success;
    syscall_ctx_helper_fixed_off_write:
        __description("syscall: helper write ctx with fixed offset"),
        __success;
    syscall_ctx_helper_unaligned_fixed_off_read:
        __description("syscall: helper unaligned read ctx with fixed offset"),
        __success;
    syscall_ctx_helper_unaligned_fixed_off_write:
        __description("syscall: helper unaligned write ctx with fixed offset"),
        __success;
    syscall_ctx_helper_var_off_read:
        __description("syscall: helper read ctx with variable offset"),
        __success;
    syscall_ctx_helper_var_off_write:
        __description("syscall: helper write ctx with variable offset"),
        __success;
    syscall_ctx_helper_unaligned_var_off_read:
        __description("syscall: helper unaligned read ctx with variable offset"),
        __success;
    syscall_ctx_helper_unaligned_var_off_write:
        __description("syscall: helper unaligned write ctx with variable offset"),
        __success;
    syscall_ctx_helper_u16_max_fixed_off_read:
        __description("syscall: reject helper read ctx past U16_MAX with fixed offset"),
        __failure,
        __msg("outside of the allowed memory range");
    syscall_ctx_helper_u16_max_fixed_off_write:
        __description("syscall: reject helper write ctx past U16_MAX with fixed offset"),
        __failure,
        __msg("outside of the allowed memory range");
    syscall_ctx_helper_u16_max_var_off_read:
        __description("syscall: reject helper read ctx past U16_MAX with variable offset"),
        __failure,
        __msg("outside of the allowed memory range");
    syscall_ctx_helper_u16_max_var_off_write:
        __description("syscall: reject helper write ctx past U16_MAX with variable offset"),
        __failure,
        __msg("outside of the allowed memory range");
    syscall_ctx_helper_zero_sized_read:
        __description("syscall: helper read zero-sized ctx access"),
        __success;
    syscall_ctx_helper_zero_sized_write:
        __description("syscall: helper write zero-sized ctx access"),
        __success;
    syscall_ctx_kfunc_fixed_off:
        __description("syscall: kfunc access ctx with fixed offset"),
        __success;
    syscall_ctx_kfunc_var_off:
        __description("syscall: kfunc access ctx with variable offset"),
        __success;
    syscall_ctx_kfunc_unaligned_fixed_off:
        __description("syscall: kfunc unaligned access ctx with fixed offset"),
        __success;
    syscall_ctx_kfunc_unaligned_var_off:
        __description("syscall: kfunc unaligned access ctx with variable offset"),
        __success;
    syscall_ctx_kfunc_u16_max_fixed_off:
        __description("syscall: reject kfunc ctx access past U16_MAX with fixed offset"),
        __failure,
        __msg("outside of the allowed memory range");
    syscall_ctx_kfunc_u16_max_var_off:
        __description("syscall: reject kfunc ctx access past U16_MAX with variable offset"),
        __failure,
        __msg("outside of the allowed memory range");
    syscall_ctx_kfunc_zero_sized:
        __description("syscall: kfunc access zero-sized ctx"),
        __success;
    no_rewrite_kprobe_fixed:
        __description("kprobe: read ctx at fixed offset"),
        __success;
    no_rewrite_kprobe_var:
        __description("kprobe: reject variable offset ctx access"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_kprobe_neg:
        __description("kprobe: reject negative offset ctx access"),
        __failure,
        __msg("invalid bpf_context access");
    no_rewrite_kprobe_helper_read_fixed:
        __description("kprobe: reject helper read ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_kprobe_helper_write_fixed:
        __description("kprobe: reject helper write ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_kprobe_helper_read_var:
        __description("kprobe: reject helper read ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_kprobe_helper_write_var:
        __description("kprobe: reject helper write ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_kprobe_helper_read_zero:
        __description("kprobe: reject helper read zero-sized ctx access"),
        __failure,
        __msg("R4 type=ctx expected=fp");
    no_rewrite_kprobe_helper_write_zero:
        __description("kprobe: reject helper write zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_kprobe_kfunc_fixed:
        __description("kprobe: reject kfunc ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_kprobe_kfunc_var:
        __description("kprobe: reject kfunc ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_kprobe_kfunc_zero:
        __description("kprobe: reject kfunc zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_tp_fixed:
        __description("tracepoint: read ctx at fixed offset"),
        __success;
    no_rewrite_tp_var:
        __description("tracepoint: reject variable offset ctx access"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_tp_neg:
        __description("tracepoint: reject negative offset ctx access"),
        __failure,
        __msg("invalid bpf_context access");
    no_rewrite_tp_helper_read_fixed:
        __description("tracepoint: reject helper read ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_tp_helper_write_fixed:
        __description("tracepoint: reject helper write ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_tp_helper_read_var:
        __description("tracepoint: reject helper read ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_tp_helper_write_var:
        __description("tracepoint: reject helper write ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_tp_helper_read_zero:
        __description("tracepoint: reject helper read zero-sized ctx access"),
        __failure,
        __msg("R4 type=ctx expected=fp");
    no_rewrite_tp_helper_write_zero:
        __description("tracepoint: reject helper write zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_tp_kfunc_fixed:
        __description("tracepoint: reject kfunc ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_tp_kfunc_var:
        __description("tracepoint: reject kfunc ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_tp_kfunc_zero:
        __description("tracepoint: reject kfunc zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_raw_tp_fixed:
        __description("raw_tp: read ctx at fixed offset"),
        __success;
    no_rewrite_raw_tp_var:
        __description("raw_tp: reject variable offset ctx access"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_raw_tp_neg:
        __description("raw_tp: reject negative offset ctx access"),
        __failure,
        __msg("invalid bpf_context access");
    no_rewrite_raw_tp_helper_read_fixed:
        __description("raw_tp: reject helper read ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_raw_tp_helper_write_fixed:
        __description("raw_tp: reject helper write ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_raw_tp_helper_read_var:
        __description("raw_tp: reject helper read ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_raw_tp_helper_write_var:
        __description("raw_tp: reject helper write ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_raw_tp_helper_read_zero:
        __description("raw_tp: reject helper read zero-sized ctx access"),
        __failure,
        __msg("R4 type=ctx expected=fp");
    no_rewrite_raw_tp_helper_write_zero:
        __description("raw_tp: reject helper write zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_raw_tp_kfunc_fixed:
        __description("raw_tp: reject kfunc ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_raw_tp_kfunc_var:
        __description("raw_tp: reject kfunc ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_raw_tp_kfunc_zero:
        __description("raw_tp: reject kfunc zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_raw_tp_w_fixed:
        __description("raw_tracepoint.w: read ctx at fixed offset"),
        __success;
    no_rewrite_raw_tp_w_var:
        __description("raw_tracepoint.w: reject variable offset ctx access"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_raw_tp_w_neg:
        __description("raw_tracepoint.w: reject negative offset ctx access"),
        __failure,
        __msg("invalid bpf_context access");
    no_rewrite_raw_tp_w_helper_read_fixed:
        __description("raw_tracepoint.w: reject helper read ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_raw_tp_w_helper_write_fixed:
        __description("raw_tracepoint.w: reject helper write ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_raw_tp_w_helper_read_var:
        __description("raw_tracepoint.w: reject helper read ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_raw_tp_w_helper_write_var:
        __description("raw_tracepoint.w: reject helper write ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_raw_tp_w_helper_read_zero:
        __description("raw_tracepoint.w: reject helper read zero-sized ctx access"),
        __failure,
        __msg("R4 type=ctx expected=fp");
    no_rewrite_raw_tp_w_helper_write_zero:
        __description("raw_tracepoint.w: reject helper write zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_raw_tp_w_kfunc_fixed:
        __description("raw_tracepoint.w: reject kfunc ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_raw_tp_w_kfunc_var:
        __description("raw_tracepoint.w: reject kfunc ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_raw_tp_w_kfunc_zero:
        __description("raw_tracepoint.w: reject kfunc zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_fentry_fixed:
        __description("fentry/bpf_modify_return_test: read ctx at fixed offset"),
        __success;
    no_rewrite_fentry_var:
        __description("fentry/bpf_modify_return_test: reject variable offset ctx access"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_fentry_neg:
        __description("fentry/bpf_modify_return_test: reject negative offset ctx access"),
        __failure,
        __msg("invalid bpf_context access");
    no_rewrite_fentry_helper_read_fixed:
        __description("fentry/bpf_modify_return_test: reject helper read ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_fentry_helper_write_fixed:
        __description("fentry/bpf_modify_return_test: reject helper write ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_fentry_helper_read_var:
        __description("fentry/bpf_modify_return_test: reject helper read ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_fentry_helper_write_var:
        __description("fentry/bpf_modify_return_test: reject helper write ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_fentry_helper_read_zero:
        __description("fentry/bpf_modify_return_test: reject helper read zero-sized ctx access"),
        __failure,
        __msg("R4 type=ctx expected=fp");
    no_rewrite_fentry_helper_write_zero:
        __description("fentry/bpf_modify_return_test: reject helper write zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_fentry_kfunc_fixed:
        __description("fentry/bpf_modify_return_test: reject kfunc ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_fentry_kfunc_var:
        __description("fentry/bpf_modify_return_test: reject kfunc ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_fentry_kfunc_zero:
        __description("fentry/bpf_modify_return_test: reject kfunc zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_cgroup_dev_fixed:
        __description("cgroup/dev: read ctx at fixed offset"),
        __success;
    no_rewrite_cgroup_dev_var:
        __description("cgroup/dev: reject variable offset ctx access"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_cgroup_dev_neg:
        __description("cgroup/dev: reject negative offset ctx access"),
        __failure,
        __msg("invalid bpf_context access");
    no_rewrite_cgroup_dev_helper_read_fixed:
        __description("cgroup/dev: reject helper read ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_cgroup_dev_helper_write_fixed:
        __description("cgroup/dev: reject helper write ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_cgroup_dev_helper_read_var:
        __description("cgroup/dev: reject helper read ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_cgroup_dev_helper_write_var:
        __description("cgroup/dev: reject helper write ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_cgroup_dev_helper_read_zero:
        __description("cgroup/dev: reject helper read zero-sized ctx access"),
        __failure,
        __msg("R4 type=ctx expected=fp");
    no_rewrite_cgroup_dev_helper_write_zero:
        __description("cgroup/dev: reject helper write zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_cgroup_dev_kfunc_fixed:
        __description("cgroup/dev: reject kfunc ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_cgroup_dev_kfunc_var:
        __description("cgroup/dev: reject kfunc ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_cgroup_dev_kfunc_zero:
        __description("cgroup/dev: reject kfunc zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_netfilter_fixed:
        __description("netfilter: read ctx at fixed offset"),
        __success;
    no_rewrite_netfilter_var:
        __description("netfilter: reject variable offset ctx access"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_netfilter_neg:
        __description("netfilter: reject negative offset ctx access"),
        __failure,
        __msg("invalid bpf_context access");
    no_rewrite_netfilter_helper_read_fixed:
        __description("netfilter: reject helper read ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_netfilter_helper_write_fixed:
        __description("netfilter: reject helper write ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_netfilter_helper_read_var:
        __description("netfilter: reject helper read ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_netfilter_helper_write_var:
        __description("netfilter: reject helper write ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_netfilter_helper_read_zero:
        __description("netfilter: reject helper read zero-sized ctx access"),
        __failure,
        __msg("R4 type=ctx expected=fp");
    no_rewrite_netfilter_helper_write_zero:
        __description("netfilter: reject helper write zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
    no_rewrite_netfilter_kfunc_fixed:
        __description("netfilter: reject kfunc ctx at fixed offset"),
        __failure,
        __msg("dereference of modified ctx ptr");
    no_rewrite_netfilter_kfunc_var:
        __description("netfilter: reject kfunc ctx with variable offset"),
        __failure,
        __msg("variable ctx access var_off=");
    no_rewrite_netfilter_kfunc_zero:
        __description("netfilter: reject kfunc zero-sized ctx access"),
        __failure,
        __msg("R1 type=ctx expected=fp");
}

#[no_mangle]
static ctx_strncmp_target: [i8; 4] = [99, 116, 120, 0];

#[no_mangle]
static ctx_snprintf_fmt: [i8; 1] = [0];

extern "C" {
    fn bpf_kfunc_call_test_mem_len_pass1(a0: *mut c_void, a1: i32);
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: context_stores_via_bpf_atomic
extern "C" fn context_stores_via_bpf_atomic() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "lock *(u32 *)(r1 + 8) += w0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: make_ptr_to_ctx_unusable
extern "C" fn make_ptr_to_ctx_unusable() {
    unsafe {
        core::arch::asm!(
            "r1 += 68;",
            "r0 = *(u32*)(r1 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unmodified_ctx_pointer_to_helper
extern "C" fn unmodified_ctx_pointer_to_helper() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "call 40;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ctx_pointer_to_helper_1
extern "C" fn ctx_pointer_to_helper_1() {
    unsafe {
        core::arch::asm!(
            "r1 += -612;",
            "r2 = 0;",
            "call 40;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ctx_pointer_to_helper_2
extern "C" fn ctx_pointer_to_helper_2() {
    unsafe {
        core::arch::asm!(
            "r1 += -612;",
            "call 46;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ctx_pointer_to_helper_3
extern "C" fn ctx_pointer_to_helper_3() {
    unsafe {
        core::arch::asm!(
            "r3 = *(u32*)(r1 + 0);",
            "r3 &= 4;",
            "r1 += r3;",
            "r2 = 0;",
            "call 40;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: or_null_check_1_ctx
extern "C" fn or_null_check_1_ctx() {
    unsafe {
        core::arch::asm!(
            "call 122;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: or_null_check_2_null
extern "C" fn or_null_check_2_null() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "call 122;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: or_null_check_3_1
extern "C" fn or_null_check_3_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "call 122;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_check_4_ctx_const
extern "C" fn null_check_4_ctx_const() {
    unsafe {
        core::arch::asm!(
            "r1 += -612;",
            "call 122;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/connect4"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_check_5_null_connect
extern "C" fn null_check_5_null_connect() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "call 122;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/post_bind4"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_check_6_null_bind
extern "C" fn null_check_6_null_bind() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "call 122;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/post_bind4"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_check_7_ctx_bind
extern "C" fn null_check_7_ctx_bind() {
    unsafe {
        core::arch::asm!(
            "call 46;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/post_bind4"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_check_8_null_bind
extern "C" fn null_check_8_null_bind() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "call 46;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_narrow_loadbpf_sockoptsk
extern "C" fn invalid_narrow_loadbpf_sockoptsk() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 4);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_narrow_loadbpf_sockoptoptval
extern "C" fn invalid_narrow_loadbpf_sockoptoptval() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 12);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_narrow_loadbpf_sockoptoptval_end
extern "C" fn invalid_narrow_loadbpf_sockoptoptval_end() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 20);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_narrow_load__sk_buffsk
extern "C" fn invalid_narrow_load__sk_buffsk() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 172);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/bind4"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_narrow_loadbpf_sock_addrsk
extern "C" fn invalid_narrow_loadbpf_sock_addrsk() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 68);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sockops"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_narrow_loadbpf_sock_opssk
extern "C" fn invalid_narrow_loadbpf_sock_opssk() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 188);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sockops"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_narrow_loadbpf_sock_opsskb_data
extern "C" fn invalid_narrow_loadbpf_sock_opsskb_data() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 196);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sockops"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_narrow_loadbpf_sock_opsskb_data_end
extern "C" fn invalid_narrow_loadbpf_sock_opsskb_data_end() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 204);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sockops"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: invalid_narrow_loadbpf_sock_opsskb_hwtstamp
extern "C" fn invalid_narrow_loadbpf_sock_opsskb_hwtstamp() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 220);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unaligned_ctx_access___sk_buffdata
extern "C" fn unaligned_ctx_access___sk_buffdata() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 77);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "netfilter"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unaligned_ctx_access_bpf_nf_ctxskb
extern "C" fn unaligned_ctx_access_bpf_nf_ctxskb() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r1 + 9);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/bind4"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: padding_ctx_access_bpf_sock_addr
extern "C" fn padding_ctx_access_bpf_sock_addr() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 60);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_lookup"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: padding_ctx_access_bpf_sk_lookup
extern "C" fn padding_ctx_access_bpf_sk_lookup() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u16 *)(r1 + 38);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: padding_ctx_access___sk_buff
extern "C" fn padding_ctx_access___sk_buff() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u16 *)(r1 + 181);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/post_bind4"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: padding_ctx_access_bpf_sock
extern "C" fn padding_ctx_access_bpf_sock() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u16 *)(r1 + 50);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_reuseport"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: padding_ctx_access_sk_reuseport_md
extern "C" fn padding_ctx_access_sk_reuseport_md() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u32 *)(r1 + 36);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

include!("hand/verifier_ctx.rs");

bpf_object!("GPL");
