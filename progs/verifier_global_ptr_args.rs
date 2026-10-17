// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]
#![feature(linkage)]

// Translation of tools/testing/selftests/bpf/progs/verifier_global_ptr_args.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_global_ptr_args.rs
// (include!d below): subprog_trusted_task_nullable, subprog_trusted_task_nullable_extra_layer, trusted_task_arg_nullable, subprog_trusted_task_nonnull, trusted_task_arg_nonnull_fail1, trusted_task_arg_nonnull_fail2, trusted_task_arg_nonnull, subprog_nullable_task_flavor, flavor_ptr_nullable, subprog_nonnull_task_flavor, flavor_ptr_nonnull, subprog_trusted_destroy, trusted_destroy_fail, subprog_trusted_acq_rel, trusted_acq_rel, subprog_untrusted_bad_tags, untrusted_bad_tags, subprog_untrusted_bad_type, untrusted_bad_type, subprog_untrusted, trusted_to_untrusted, anything_to_untrusted, subprog_untrusted2, untrusted_to_trusted, subprog_void_untrusted, subprog_char_untrusted, subprog_enum_untrusted, trusted_to_untrusted_mem, subprog_write_mem_arg, trusted_btf_field_to_writable_mem, anything_to_untrusted_mem, subprog_pkt_ptr_no_change, pkt_ptr_to_global_mem_arg_no_change, subprog_pkt_ptr_changes_data, pkt_ptr_to_global_mem_arg_changes_data.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_global_ptr_args` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: subprog_trusted_task_nullable subprog_trusted_task_nullable_extra_layer trusted_task_arg_nullable null_btf_id_arg_global_subprog subprog_trusted_task_nonnull trusted_task_arg_nonnull_fail1 trusted_task_arg_nonnull_fail2 trusted_task_arg_nonnull subprog_nullable_task_flavor flavor_ptr_nullable subprog_nonnull_task_flavor flavor_ptr_nonnull subprog_trusted_destroy trusted_destroy_fail subprog_trusted_acq_rel trusted_acq_rel subprog_untrusted_bad_tags untrusted_bad_tags subprog_untrusted_bad_type untrusted_bad_type subprog_untrusted trusted_to_untrusted anything_to_untrusted subprog_untrusted2 untrusted_to_trusted subprog_void_untrusted subprog_char_untrusted subprog_enum_untrusted trusted_to_untrusted_mem subprog_write_mem_arg trusted_btf_field_to_writable_mem anything_to_untrusted_mem subprog_pkt_ptr_no_change pkt_ptr_to_global_mem_arg_no_change subprog_pkt_ptr_changes_data pkt_ptr_to_global_mem_arg_changes_data

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

// (from the hand file)
// BTF_TYPE_ID: task_struct_id struct task_struct
// BTF_TYPE_ID: bpf_verifier_env_id struct bpf_verifier_env

use bpf_rs_core::{arg_tags, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    trusted_task_arg_nullable:
        __success,
        __log_level("2"),
        __msg("Validating subprog_trusted_task_nullable() func#1..."),
        __msg(": R1=trusted_ptr_or_null_task_struct(");
    null_btf_id_arg_global_subprog:
        __failure,
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("R1 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_");
    trusted_task_arg_nonnull_fail1:
        __failure,
        __log_level("2"),
        __msg("Possibly NULL pointer passed to trusted R1"),
        __msg("Caller passes invalid args into func#1 ('subprog_trusted_task_nonnull')");
    trusted_task_arg_nonnull_fail2:
        __failure,
        __log_level("2"),
        __msg("Possibly NULL pointer passed to trusted R1"),
        __msg("Caller passes invalid args into func#1 ('subprog_trusted_task_nonnull')");
    trusted_task_arg_nonnull:
        __success,
        __log_level("2"),
        __msg("Validating subprog_trusted_task_nonnull() func#1..."),
        __msg(": R1=trusted_ptr_task_struct(");
    flavor_ptr_nullable:
        __success,
        __log_level("2"),
        __msg("Validating subprog_nullable_task_flavor() func#1..."),
        __msg(": R1=trusted_ptr_or_null_task_struct(");
    flavor_ptr_nonnull:
        __success,
        __log_level("2"),
        __msg("Validating subprog_nonnull_task_flavor() func#1..."),
        __msg(": R1=trusted_ptr_task_struct(");
    trusted_destroy_fail:
        __failure,
        __log_level("2"),
        __msg("release function bpf_task_release expects referenced PTR_TO_BTF_ID passed to R1");
    trusted_acq_rel:
        __success,
        __log_level("2");
    untrusted_bad_tags:
        __failure,
        __msg("arg#0 untrusted cannot be combined with any other tags");
    untrusted_bad_type:
        __failure,
        __msg("arg#0 reference type('STRUCT local_type_wont_be_accepted') has no matches");
    trusted_to_untrusted:
        __success,
        __log_level("2"),
        __msg("r1 = {{.*}}; {{.*}}R1=trusted_ptr_task_struct()"),
        __msg("Func#1 ('subprog_untrusted') is global and assumed valid."),
        __msg("Validating subprog_untrusted() func#1..."),
        __msg(": R1=untrusted_ptr_task_struct");
    anything_to_untrusted:
        __success;
    untrusted_to_trusted:
        __failure,
        __msg("R1 type=untrusted_ptr_ expected=ptr_, trusted_ptr_, rcu_ptr_"),
        __msg("Caller passes invalid args into func#{{.*}} ('subprog_trusted_task_nullable')");
    trusted_to_untrusted_mem:
        __success,
        __log_level("2"),
        __msg("r1 = {{.*}}; {{.*}}R1=trusted_ptr_task_struct()"),
        __msg("Func#1 ('subprog_void_untrusted') is global and assumed valid."),
        __msg("Validating subprog_void_untrusted() func#1..."),
        __msg(": R1=rdonly_untrusted_mem(sz=0)");
    trusted_btf_field_to_writable_mem:
        __failure,
        __msg("only read is supported");
    anything_to_untrusted_mem:
        __success;
    pkt_ptr_to_global_mem_arg_no_change:
        __success;
    pkt_ptr_to_global_mem_arg_changes_data:
        __failure,
        __log_level("2"),
        __msg("cannot pass packet pointer R2"),
        __msg("function may change packet data"),
        __msg("Caller passes invalid args into func#{{[0-9]+}} ('subprog_pkt_ptr_changes_data')");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
arg_tags! {
    subprog_trusted_task_nullable: 0: "arg:nullable", 0: "arg:trusted";
    subprog_trusted_task_nullable_extra_layer: 0: "arg:nullable", 0: "arg:trusted";
    subprog_trusted_task_nonnull: 0: "arg:trusted";
    subprog_nullable_task_flavor: 0: "arg:nullable", 0: "arg:trusted";
    subprog_nonnull_task_flavor: 0: "arg:trusted";
    subprog_trusted_destroy: 0: "arg:trusted";
    subprog_trusted_acq_rel: 0: "arg:trusted";
    subprog_untrusted_bad_tags: 0: "arg:nullable", 0: "arg:untrusted";
    subprog_untrusted_bad_type: 0: "arg:untrusted";
    subprog_untrusted: 0: "arg:untrusted";
    subprog_untrusted2: 0: "arg:untrusted";
    subprog_void_untrusted: 0: "arg:untrusted";
    subprog_char_untrusted: 0: "arg:untrusted";
    subprog_enum_untrusted: 0: "arg:untrusted";
    subprog_pkt_ptr_changes_data: 0: "arg:ctx";
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct task_struct___local {

}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct local_type_wont_be_accepted {

}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct pkt_arg {
    x: u64,
    pad: [u8; 56],
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

#[no_mangle]
static mut mem: [i8; 16] = [0; 16];

#[no_mangle]
static mut offset: u32 = 0;

extern "C" {
    fn bpf_task_acquire(a0: *mut c_void) -> *mut c_void;
    fn bpf_task_release(a0: *mut c_void);
    fn bpf_rdonly_cast(a0: *mut c_void, a1: u32) -> *mut c_void;
}

#[link_section = "?tp_btf/task_newtask"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_btf_id_arg_global_subprog
extern "C" fn null_btf_id_arg_global_subprog() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 42;",
            "if r0 > 42 goto 1f;",
            "r1 = 0;",
            "1:",
            "call {subprog_trusted_task_nullable};",
            "r0 = 0;",
            "exit;",
            subprog_trusted_task_nullable = sym subprog_trusted_task_nullable,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

include!("hand/verifier_global_ptr_args.rs");

bpf_object!("GPL");
