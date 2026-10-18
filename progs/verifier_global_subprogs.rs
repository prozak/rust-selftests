// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]
#![feature(linkage)]

// Translation of tools/testing/selftests/bpf/progs/verifier_global_subprogs.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_global_subprogs.rs
// (include!d below): global_bad, global_good, global_calls_bad, global_calls_good_only, global_dead, chained_global_func_calls_success, chained_global_func_calls_bad, global_unsupp, guarded_unsupp_global_called, unguarded_unsupp_global_called, subprog_nullable_ptr_bad, arg_tag_nullable_ptr_fail, subprog_user_anon_mem, anon_user_mem_invalid, anon_user_mem_valid, subprog_user_anon_mem_huge, anon_user_mem_huge_size_invalid, subprog_nonnull_ptr_good, arg_tag_nonnull_ptr_good, arg_tag_nonnull_ptr_null_bad, subprog_ctx_tag, raw_tp_canonical, raw_tp_u64_array, arg_tag_ctx_raw_tp, arg_tag_ctx_raw_tp_writable, arg_tag_ctx_raw_tp_btf, tp_whatever, arg_tag_ctx_tp, kprobe_subprog_pt_regs, kprobe_subprog_typedef, arg_tag_ctx_kprobe, perf_subprog_regs, perf_subprog_typedef, perf_subprog_canonical, arg_tag_ctx_perf, iter_subprog_void, iter_subprog_typed, arg_tag_ctx_iter_task, tracing_subprog_void, tracing_subprog_u64, arg_tag_ctx_fentry, arg_tag_ctx_fexit, arg_tag_ctx_fmod_ret, arg_tag_ctx_lsm, arg_tag_ctx_struct_ops, arg_tag_ctx_syscall, syscall_array_bpf_for, arg_tag_ctx_syscall_bpf_for, syscall_tailcall_target, arg_tag_ctx_syscall_tailcall, arg_tag_ctx_syscall_tailcall_fixed_off_bad, arg_tag_ctx_syscall_tailcall_var_off_bad, arg_tag_ctx_syscall_fixed_off_bad, arg_tag_ctx_syscall_var_off_bad, subprog_dynptr, arg_tag_dynptr, foo, return_from_void_global, static_calls_global, loop_cb_calls_static, global_calls_loop, recursion_via_global_func_and_callback.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_global_subprogs` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: global_bad global_good global_calls_bad global_calls_good_only global_dead chained_global_func_calls_success chained_global_func_calls_bad global_unsupp guarded_unsupp_global_called unguarded_unsupp_global_called subprog_nullable_ptr_bad arg_tag_nullable_ptr_fail subprog_user_anon_mem anon_user_mem_invalid anon_user_mem_valid subprog_user_anon_mem_huge anon_user_mem_huge_size_invalid subprog_nonnull_ptr_good arg_tag_nonnull_ptr_good arg_tag_nonnull_ptr_null_bad subprog_ctx_tag raw_tp_canonical raw_tp_u64_array arg_tag_ctx_raw_tp arg_tag_ctx_raw_tp_writable arg_tag_ctx_raw_tp_btf tp_whatever arg_tag_ctx_tp kprobe_subprog_pt_regs kprobe_subprog_typedef arg_tag_ctx_kprobe perf_subprog_regs perf_subprog_typedef perf_subprog_canonical arg_tag_ctx_perf iter_subprog_void iter_subprog_typed arg_tag_ctx_iter_task tracing_subprog_void tracing_subprog_u64 arg_tag_ctx_fentry arg_tag_ctx_fexit arg_tag_ctx_fmod_ret arg_tag_ctx_lsm arg_tag_ctx_struct_ops arg_tag_ctx_syscall syscall_array_bpf_for arg_tag_ctx_syscall_bpf_for syscall_tailcall_target arg_tag_ctx_syscall_tailcall arg_tag_ctx_syscall_tailcall_fixed_off_bad arg_tag_ctx_syscall_tailcall_var_off_bad arg_tag_ctx_syscall_fixed_off_bad arg_tag_ctx_syscall_var_off_bad subprog_dynptr arg_tag_dynptr foo return_from_void_global static_calls_global loop_cb_calls_static global_calls_loop recursion_via_global_func_and_callback

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

// a `*mut c_void` is the C's `void *` in BTF (scripts/btf_rename.py)
// BTF_C_VOID: c_void

// (from the hand file)
// translint: allow(test-tags:chained_global_func_calls_success)

use bpf_rs_core::{arg_tags, bpf_object, test_tags};
use btf_macros::btf;
use core::ffi::c_void;

test_tags! {
    chained_global_func_calls_success:
        __success,
        __log_level("6"),
        __msg("('global_calls_good_only') is global and assumed valid."),
        __msg("Validating global_good() func"),
        __msg("('global_good') is safe for any args that match its prototype"),
        __msg("subprog 0 (chained_global_func_calls_success) main insns_self 7 insns_total 7 stack"),
        __msg("subprog {{[0-9]+}} (global_calls_good_only) global insns_self 2 insns_total 2 stack"),
        __msg("subprog {{[0-9]+}} (global_good) global insns_self 3 insns_total 3 stack"),
        __msg("processed 12 insns");
    chained_global_func_calls_bad:
        __failure,
        __log_level("2"),
        __msg("('global_calls_bad') is global and assumed valid."),
        __msg("Validating global_bad() func"),
        __msg("math between map_value pointer and register");
    guarded_unsupp_global_called:
        __success;
    unguarded_unsupp_global_called:
        __failure,
        __log_level("2"),
        __msg("Func#1 ('global_unsupp') is global and assumed valid."),
        __msg("Validating global_unsupp() func#1..."),
        __msg("value is outside of the allowed memory range");
    arg_tag_nullable_ptr_fail:
        __failure,
        __log_level("2"),
        __msg("invalid mem access 'mem_or_null'");
    anon_user_mem_invalid:
        __failure,
        __log_level("2"),
        __msg("Caller passes invalid args into func#1 ('subprog_user_anon_mem')");
    anon_user_mem_valid:
        __success,
        __log_level("2"),
        __msg("Func#1 ('subprog_user_anon_mem') is safe for any args that match its prototype");
    anon_user_mem_huge_size_invalid:
        __failure,
        __log_level("2"),
        __msg("R1 memory size 4294967292 is too large");
    arg_tag_nonnull_ptr_good:
        __success,
        __log_level("2");
    arg_tag_nonnull_ptr_null_bad:
        __failure,
        __log_level("2"),
        __msg("Possibly NULL pointer passed to trusted R1");
    arg_tag_ctx_raw_tp:
        __success,
        __log_level("2");
    arg_tag_ctx_raw_tp_writable:
        __success,
        __log_level("2");
    arg_tag_ctx_raw_tp_btf:
        __success,
        __log_level("2");
    arg_tag_ctx_tp:
        __success,
        __log_level("2");
    arg_tag_ctx_kprobe:
        __success,
        __log_level("2");
    arg_tag_ctx_perf:
        __success,
        __log_level("2");
    arg_tag_ctx_iter_task:
        __success,
        __log_level("2");
    arg_tag_ctx_fentry:
        __success,
        __log_level("2");
    arg_tag_ctx_fexit:
        __success,
        __log_level("2");
    arg_tag_ctx_fmod_ret:
        __success,
        __log_level("2");
    arg_tag_ctx_lsm:
        __success,
        __log_level("2");
    arg_tag_ctx_struct_ops:
        __success,
        __log_level("2");
    arg_tag_ctx_syscall:
        __success,
        __log_level("2");
    arg_tag_ctx_syscall_bpf_for:
        __success,
        __log_level("2");
    syscall_tailcall_target:
        __auxiliary;
    arg_tag_ctx_syscall_tailcall:
        __success,
        __log_level("2");
    arg_tag_ctx_syscall_tailcall_fixed_off_bad:
        __failure,
        __log_level("2"),
        __msg("dereference of modified ctx ptr R1 off=8 disallowed");
    arg_tag_ctx_syscall_tailcall_var_off_bad:
        __failure,
        __log_level("2"),
        __msg("variable ctx access var_off=(0x0; 0x4) disallowed");
    arg_tag_ctx_syscall_fixed_off_bad:
        __failure,
        __log_level("2"),
        __msg("dereference of modified ctx ptr R1 off=8 disallowed");
    arg_tag_ctx_syscall_var_off_bad:
        __failure,
        __log_level("2"),
        __msg("variable ctx access var_off=(0x0; 0x4) disallowed");
    arg_tag_dynptr:
        __success,
        __log_level("2");
    return_from_void_global:
        __failure,
        __msg("R0 !read_ok");
    recursion_via_global_func_and_callback:
        __failure,
        __msg("recursive call from global_calls_loop() to loop_cb_calls_static()");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
arg_tags! {
    subprog_nonnull_ptr_good: 0: "arg:nonnull", 1: "arg:nonnull";
    subprog_ctx_tag: 0: "arg:ctx";
    raw_tp_canonical: 0: "arg:ctx";
    raw_tp_u64_array: 0: "arg:ctx";
    tp_whatever: 0: "arg:ctx";
    kprobe_subprog_pt_regs: 0: "arg:ctx";
    kprobe_subprog_typedef: 0: "arg:ctx";
    perf_subprog_regs: 0: "arg:ctx";
    perf_subprog_typedef: 0: "arg:ctx";
    perf_subprog_canonical: 0: "arg:ctx";
    iter_subprog_void: 0: "arg:ctx";
    iter_subprog_typed: 0: "arg:ctx";
    tracing_subprog_void: 0: "arg:ctx";
    tracing_subprog_u64: 0: "arg:ctx";
    syscall_array_bpf_for: 0: "arg:ctx";
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_raw_tracepoint_args {
    args: [u64; 0],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct whatever {

}

/// An opaque stand-in for the kernel's: only pointed at.
#[allow(non_camel_case_types)]
#[btf]
struct pt_regs {}

/// An opaque stand-in for the kernel's: only pointed at.
#[allow(non_camel_case_types)]
#[btf]
struct bpf_perf_event_data {}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_iter__task__anon0 {
    meta: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_iter__task__anon1 {
    task: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_iter__task {
    __anon0: bpf_iter__task__anon0,
    __anon1: bpf_iter__task__anon1,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct xdp_md {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union __sk_buff__anon26 {
    flow_keys: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union __sk_buff__anon30 {
    sk: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct __sk_buff {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    tc_index: u32,
    cb: [u32; 5],
    hash: u32,
    tc_classid: u32,
    data: u32,
    data_end: u32,
    napi_id: u32,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    data_meta: u32,
    __anon26: __sk_buff__anon26,
    tstamp: u64,
    wire_len: u32,
    gso_segs: u32,
    __anon30: __sk_buff__anon30,
    gso_size: u32,
    tstamp_type: u8,
    hwtstamp: u64,
}

/// The C's struct_ops map value: the kernel's struct of this name.
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
struct bpf_dummy_ops {
    test_1: extern "C" fn(*mut u64) -> i32,
    test_2: *const c_void,
    test_sleepable: *const c_void,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct syscall_prog_array {
    r#type: *const [i32; 3],
    max_entries: *const [i32; 1],
    key_size: *const [i32; 4],
    values: [*const c_void; 1],
}
unsafe impl Sync for syscall_prog_array {}

#[link_section = ".maps"]
#[no_mangle]
static syscall_prog_array: syscall_prog_array = syscall_prog_array {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [syscall_tailcall_target as extern "C" fn(*mut c_void) -> i32 as *const c_void],
};

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut arr: [i32; 1] = [0];

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut unkn_idx: i32 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut stack: [i64; 128] = [0; 128];

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut acc: i32 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut x: i32 = 47;

#[no_mangle]
#[allow(non_upper_case_globals)]
static call_dead_subprog: bool = false;

#[no_mangle]
#[allow(non_upper_case_globals)]
static skip_unsupp_global: bool = true;

#[link_section = ".struct_ops"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static mut dummy_1: bpf_dummy_ops = bpf_dummy_ops { test_1: arg_tag_ctx_struct_ops, test_2: core::ptr::null(), test_sleepable: core::ptr::null() };

extern "C" {
    fn bpf_iter_num_new(a0: *mut c_void, a1: i32, a2: i32) -> i32;
    fn bpf_iter_num_next(a0: *mut c_void) -> *mut c_void;
    fn bpf_iter_num_destroy(a0: *mut c_void);
    fn bpf_dynptr_slice(a0: *mut c_void, a1: u64, a2: *mut c_void, a3: u64) -> *mut c_void;
    fn bpf_dynptr_from_xdp(a0: *mut c_void, a1: u64, a2: *mut c_void) -> i32;
}

include!("hand/verifier_global_subprogs.rs");

bpf_object!("GPL");
