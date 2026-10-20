// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/stack_arg_precision.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/stack_arg_precision.rs
// (include!d below): __btf_kfunc_gen.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py stack_arg_precision` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: __btf_kfunc_gen subprog_call_mem_kfunc stack_arg_precision_bpf2bpf

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

// a `*mut c_void` is the C's `void *` in BTF (scripts/btf_rename.py)
// BTF_C_VOID: c_void

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    stack_arg_precision_bpf2bpf:
        __description("stack_arg: precision backtracking across bpf2bpf call for kfunc"),
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __btf_func_path("btf__stack_arg_precision.bpf.o"),
        __msg("mark_precise: frame1: last_idx 26 first_idx 13 subseq_idx -1"),
        __msg("mark_precise: frame1: regs= stack= before 25: (b7) r5 = 5"),
        __msg("mark_precise: frame1: regs= stack= before 24: (b7) r4 = 4"),
        __msg("mark_precise: frame1: regs= stack= before 23: (b7) r3 = 3"),
        __msg("mark_precise: frame1: regs= stack= before 22: (b7) r2 = 2"),
        __msg("mark_precise: frame1: regs= stack= before 21: (b7) r1 = 1"),
        __msg("mark_precise: frame1: regs= stack= before 20: (7b) *(u64 *)(r11 -16) = r1"),
        __msg("mark_precise: frame1: regs=r1 stack= before 19: (7b) *(u64 *)(r11 -8) = r2"),
        __msg("mark_precise: frame1: regs=r1 stack= before 18: (07) r2 += -8"),
        __msg("mark_precise: frame1: regs=r1 stack= before 17: (bf) r2 = r10"),
        __msg("mark_precise: frame1: regs=r1 stack= before 16: (7b) *(u64 *)(r10 -8) = r2"),
        __msg("mark_precise: frame1: regs=r1 stack= before 14: (18) r2 = 0x807060504030201"),
        __msg("mark_precise: frame1: regs=r1 stack= before 13: (79) r1 = *(u64 *)(r11 +8)"),
        __msg("mark_precise: frame1: parent state regs= stack=:  frame1: R10=fp0"),
        __msg("mark_precise: frame0: parent state regs= stack=:  R10=fp0"),
        __msg("mark_precise: frame1: last_idx 11 first_idx 11 subseq_idx 13"),
        __msg("mark_precise: frame1: regs= stack= before 11: (85) call pc+1"),
        __msg("mark_precise: frame0: parent state regs= stack=:  R1=1 R2=2 R3=3 R4=4 R5=5 R10=fp0"),
        __msg("mark_precise: frame0: last_idx 9 first_idx 7 subseq_idx 11"),
        __msg("mark_precise: frame0: regs= stack= before 9: (05) goto pc+1"),
        __msg("mark_precise: frame0: regs= stack= before 8: (7a) *(u64 *)(r11 -8) = 4"),
        __msg("mark_precise: frame1: last_idx 26 first_idx 13 subseq_idx -1 "),
        __msg("mark_precise: frame1: regs= stack= before 25: (b7) r5 = 5"),
        __msg("mark_precise: frame1: regs= stack= before 24: (b7) r4 = 4"),
        __msg("mark_precise: frame1: regs= stack= before 23: (b7) r3 = 3"),
        __msg("mark_precise: frame1: regs= stack= before 22: (b7) r2 = 2"),
        __msg("mark_precise: frame1: regs= stack= before 21: (b7) r1 = 1"),
        __msg("mark_precise: frame1: regs= stack= before 20: (7b) *(u64 *)(r11 -16) = r1"),
        __msg("mark_precise: frame1: regs=r1 stack= before 19: (7b) *(u64 *)(r11 -8) = r2"),
        __msg("mark_precise: frame1: regs=r1 stack= before 18: (07) r2 += -8"),
        __msg("mark_precise: frame1: regs=r1 stack= before 17: (bf) r2 = r10"),
        __msg("mark_precise: frame1: regs=r1 stack= before 16: (7b) *(u64 *)(r10 -8) = r2"),
        __msg("mark_precise: frame1: regs=r1 stack= before 14: (18) r2 = 0x807060504030201"),
        __msg("mark_precise: frame1: regs=r1 stack= before 13: (79) r1 = *(u64 *)(r11 +8)"),
        __msg("mark_precise: frame1: parent state regs= stack=:  frame1: R10=fp0"),
        __msg("mark_precise: frame0: parent state regs= stack=:  R10=fp0"),
        __msg("mark_precise: frame1: last_idx 11 first_idx 11 subseq_idx 13 "),
        __msg("mark_precise: frame1: regs= stack= before 11: (85) call pc+1"),
        __msg("mark_precise: frame0: parent state regs= stack=:  R1=1 R2=2 R3=3 R4=4 R5=5 R10=fp0"),
        __msg("mark_precise: frame0: last_idx 10 first_idx 10 subseq_idx 11 "),
        __msg("mark_precise: frame0: regs= stack= before 10: (7a) *(u64 *)(r11 -8) = 6");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
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

extern "C" {
    fn bpf_kfunc_call_stack_arg_mem(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: *mut c_void, a6: i32) -> u64;
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_call_mem_kfunc
extern "C" fn subprog_call_mem_kfunc(_a: i64, _b: i64, _c: i64, _d: i64, _e: i64, _size: i64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "r1 = *(u64 *)(r11 + 8);",
            "r2 = 0x0807060504030201 ll;",
            "*(u64 *)(r10 - 8) = r2;",
            "r2 = r10;",
            "r2 += -8;",
            "*(u64 *)(r11 - 8) = r2;",
            "*(u64 *)(r11 - 16) = r1;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "call {bpf_kfunc_call_stack_arg_mem};",
            "exit;",
            bpf_kfunc_call_stack_arg_mem = sym bpf_kfunc_call_stack_arg_mem,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_arg_precision_bpf2bpf
extern "C" fn stack_arg_precision_bpf2bpf() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r1 = 1;",
            "r2 = 2;",
            "r3 = 3;",
            "r4 = 4;",
            "r5 = 5;",
            "if r6 < 2 goto l0_0;",
            "*(u64 *)(r11 - 8) = 4;",
            "goto l1_0;",
            "l0_0:",
            "*(u64 *)(r11 - 8) = 6;",
            "l1_0:",
            "call {subprog_call_mem_kfunc};",
            "exit;",
            subprog_call_mem_kfunc = sym subprog_call_mem_kfunc,
            options(nostack)
        );
    }
}

include!("hand/stack_arg_precision.rs");

bpf_object!("GPL");
