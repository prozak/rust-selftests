// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_iterating_callbacks.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_iterating_callbacks.rs
// (include!d below): unsafe_on_2nd_iter_cb, unsafe_on_2nd_iter, unsafe_on_zero_iter_cb, unsafe_on_zero_iter, widening_cb, widening, loop_detection_cb, loop_detection, for_each_map_elem_cb, unsafe_for_each_map_elem, ringbuf_drain_cb, unsafe_ringbuf_drain, find_vma_cb, unsafe_find_vma, iter_limit_cb, bpf_loop_iter_limit_ok, bpf_loop_iter_limit_overflow, iter_limit_level2a_cb, iter_limit_level2b_cb, iter_limit_level1_cb, bpf_loop_iter_limit_nested, iter_limit_bug, cond_break1, cond_break2, loop, cond_break3, cond_break4, static_subprog, cond_break5, loop_inside_iter, loop_inside_iter_signed, loop_inside_iter_volatile_limit, test1, test2, test3, test4.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_iterating_callbacks` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: unsafe_on_2nd_iter_cb unsafe_on_2nd_iter unsafe_on_zero_iter_cb unsafe_on_zero_iter widening_cb widening loop_detection_cb loop_detection for_each_map_elem_cb unsafe_for_each_map_elem ringbuf_drain_cb unsafe_ringbuf_drain find_vma_cb unsafe_find_vma iter_limit_cb bpf_loop_reject_pointer bpf_loop_iter_limit_ok bpf_loop_iter_limit_overflow iter_limit_level2a_cb iter_limit_level2b_cb iter_limit_level1_cb bpf_loop_iter_limit_nested iter_limit_bug_cb jgt_imm64_and_may_goto may_goto_self may_goto_neg_off iter_limit_bug ja_and_may_goto ja_and_may_goto2 jlt_and_may_goto gotol_and_may_goto ja_and_may_goto_subprog subprog_with_may_goto cond_break1 cond_break2 loop cond_break3 cond_break4 static_subprog cond_break5 loop_inside_iter loop_inside_iter_signed loop_inside_iter_volatile_limit test1 test2 test3 test4 check_add_const check_add_const_3regs check_add_const_3regs_2if check_add_const_regsafe_off

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    unsafe_on_2nd_iter:
        __failure,
        __msg("R1 type=scalar expected=fp");
    unsafe_on_zero_iter:
        __failure,
        __msg("invalid access to map value, value_size=2 off=32 size=1");
    widening:
        __success;
    loop_detection:
        __failure,
        __msg("infinite loop detected");
    unsafe_for_each_map_elem:
        __failure,
        __msg("invalid access to map value, value_size=2 off=32 size=1");
    unsafe_ringbuf_drain:
        __failure,
        __msg("invalid access to map value, value_size=2 off=32 size=1");
    unsafe_find_vma:
        __failure,
        __msg("invalid access to map value, value_size=2 off=32 size=1");
    bpf_loop_reject_pointer:
        __failure,
        __msg("R1 type=ctx expected=scalar");
    bpf_loop_iter_limit_ok:
        __success;
    bpf_loop_iter_limit_overflow:
        __failure,
        __msg("invalid access to map value, value_size=2 off=2 size=1");
    bpf_loop_iter_limit_nested:
        __success,
        __retval("111111");
    jgt_imm64_and_may_goto:
        __failure,
        __msg("infinite loop detected at insn 2");
    may_goto_self:
        __failure,
        __msg("infinite loop detected at insn 1");
    may_goto_neg_off:
        __success,
        __retval("0");
    iter_limit_bug:
        __failure,
        __flag("BPF_F_TEST_STATE_FREQ");
    ja_and_may_goto:
        __success,
        __retval("0");
    ja_and_may_goto2:
        __success,
        __retval("0");
    jlt_and_may_goto:
        __success,
        __retval("0");
    gotol_and_may_goto:
        __success,
        __retval("0");
    ja_and_may_goto_subprog:
        __success,
        __retval("0");
    cond_break1:
        __success,
        __retval("0xd495cdc0");
    cond_break2:
        __success,
        __retval("999000000");
    cond_break3:
        __success,
        __retval("0x6a5a2920");
    cond_break4:
        __success,
        __retval("1");
    cond_break5:
        __success,
        __retval("1");
    loop_inside_iter:
        __success,
        __flag("BPF_F_TEST_STATE_FREQ");
    loop_inside_iter_signed:
        __success,
        __flag("BPF_F_TEST_STATE_FREQ");
    loop_inside_iter_volatile_limit:
        __success,
        __flag("BPF_F_TEST_STATE_FREQ");
    test1:
        __success;
    test2:
        __success;
    test3:
        __success;
    test4:
        __success;
    check_add_const:
        __description("check add const"),
        __success;
    check_add_const_3regs:
        __failure,
        __msg("*(u8 *)(r7 +0) = r0"),
        __msg("invalid access to map value, value_size=10 off=10 size=1");
    check_add_const_3regs_2if:
        __failure,
        __msg("*(u8 *)(r8 -1) = r0"),
        __msg("invalid access to map value, value_size=10 off=10 size=1");
    check_add_const_regsafe_off:
        __failure,
        __flag("BPF_F_TEST_STATE_FREQ");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct buf_context {
    buf: *mut i8,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct num_context {
    i: u64,
    j: u64,
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

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct __anon_type637 {
    a: i32,
    b: i32,
}

bpf_map! {
    map {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 8],
        key: *const u32,
        value: *const u64,
    }
}

bpf_map! {
    ringbuf {
        r#type: *const [i32; 31],
        max_entries: *const [i32; 8],
    }
}

#[no_mangle]
static mut tmp_var: i32 = 0;

#[no_mangle]
static mut zero: i32 = 0;

#[no_mangle]
static mut arr: [i8; 1000000] = [0; 1000000];

#[no_mangle]
static mut choice_arr: [u8; 2] = [0, 1];

#[link_section = ".data.arr2"]
#[no_mangle]
static mut arr2: [i8; 1000] = [0; 1000];

#[link_section = ".data.arr_foo"]
#[no_mangle]
static mut arr_foo: [__anon_type637; 1000] = [__anon_type637 { a: 0, b: 0 }; 1000];

#[link_section = ".data.arr_long"]
#[no_mangle]
static mut arr_long: [i64; 1000] = [0; 1000];

#[link_section = ".data.buf"]
#[no_mangle]
static mut buf: [i8; 10] = [0; 10];

#[no_mangle]
static limit: i32 = 1000;

extern "C" {
    fn bpf_iter_num_new(a0: *mut c_void, a1: i32, a2: i32) -> i32;
    fn bpf_iter_num_next(a0: *mut c_void) -> *mut c_void;
    fn bpf_iter_num_destroy(a0: *mut c_void);
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_loop_reject_pointer
extern "C" fn bpf_loop_reject_pointer() {
    unsafe {
        core::arch::asm!(
            "r2 = {iter_limit_cb};",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "exit;",
            iter_limit_cb = in(reg) iter_limit_cb as usize,
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_limit_bug_cb
extern "C" fn iter_limit_bug_cb() {
    unsafe {
        core::arch::asm!(
            "r9 = r2;",
            "call 7;",
            "r1 = r0;",
            "r2 = 42;",
            "r0 = 0;",
            "if r1 == 0x1 goto 1f;",
            "if r1 == 0x2 goto 2f;",
            "*(u64 *)(r9 + 16) = r2;",
            "exit;",
            "1:",
            "*(u64 *)(r9 + 0) = r2;",
            "exit;",
            "2:",
            "*(u64 *)(r9 + 8) = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jgt_imm64_and_may_goto
extern "C" fn jgt_imm64_and_may_goto() {
    unsafe {
        core::arch::asm!(
            "r0 = {tmp_var} ll;",
            "l0_0:",
            ".byte 0xe5;",
            ".byte 0;",
            ".short -3;",
            ".long 0;",
            "if r0 > 10 goto l0_0;",
            "r0 = 0;",
            "exit;",
            tmp_var = sym tmp_var,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_goto_self
extern "C" fn may_goto_self() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32 *)(r10 - 4);",
            "l0_1:",
            ".byte 0xe5;",
            ".byte 0;",
            ".short -1;",
            ".long 0;",
            "if r0 > 10 goto l0_1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: may_goto_neg_off
extern "C" fn may_goto_neg_off() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32 *)(r10 - 4);",
            "goto l0_2;",
            "goto l1_2;",
            "l0_2:",
            ".byte 0xe5;",
            ".byte 0;",
            ".short -2;",
            ".long 0;",
            "if r0 > 10 goto l0_2;",
            "l1_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ja_and_may_goto
extern "C" fn ja_and_may_goto() {
    unsafe {
        core::arch::asm!(
            "l0_3:",
            ".byte 0xe5;",
            ".byte 0;",
            ".short 1;",
            ".long 0;",
            "goto l0_3;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ja_and_may_goto2
extern "C" fn ja_and_may_goto2() {
    unsafe {
        core::arch::asm!(
            "l0_4:",
            "r0 = 0;",
            ".byte 0xe5;",
            ".byte 0;",
            ".short 1;",
            ".long 0;",
            "goto l0_4;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jlt_and_may_goto
extern "C" fn jlt_and_may_goto() {
    unsafe {
        core::arch::asm!(
            "l0_5:",
            "call 118;",
            ".byte 0xe5;",
            ".byte 0;",
            ".short 1;",
            ".long 0;",
            "if r0 < 10 goto l0_5;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: gotol_and_may_goto
extern "C" fn gotol_and_may_goto() {
    unsafe {
        core::arch::asm!(
            "l0_6:",
            "r0 = 0;",
            ".byte 0xe5;",
            ".byte 0;",
            ".short 1;",
            ".long 0;",
            "gotol l0_6;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ja_and_may_goto_subprog
extern "C" fn ja_and_may_goto_subprog() {
    unsafe {
        core::arch::asm!(
            "call {subprog_with_may_goto};",
            "exit;",
            subprog_with_may_goto = sym subprog_with_may_goto,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_with_may_goto
extern "C" fn subprog_with_may_goto() {
    unsafe {
        core::arch::asm!(
            "l0_7:",
            ".byte 0xe5;",
            ".byte 0;",
            ".short 1;",
            ".long 0;",
            "goto l0_7;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_add_const
extern "C" fn check_add_const() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "if r0 > 9 goto l1_8;",
            "l0_8:",
            "r1 = {buf};",
            "r2 = r0;",
            "r1 += r2;",
            "r3 = *(u8 *)(r1 +0);",
            ".byte 0xe5;",
            ".byte 0;",
            ".short 4;",
            ".long 0;",
            "r0 = r2;",
            "r0 += 1;",
            "if r2 < 9 goto l0_8;",
            "exit;",
            "l1_8:",
            "r0 = 0;",
            "exit;",
            buf = in(reg) core::ptr::addr_of!(buf),
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_add_const_3regs
extern "C" fn check_add_const_3regs() {
    unsafe {
        core::arch::asm!(
            "r6 = {buf};",
            "r7 = {buf};",
            "call 5;",
            "r1 = r0;",
            "r2 = r0;",
            "r1 += 1;",
            "r2 += 2;",
            "if r0 > 8 goto 1f;",
            "r6 += r1;",
            "r7 += r2;",
            "*(u8 *)(r6 +0) = r0;",
            "*(u8 *)(r7 +0) = r0;",
            "1:",
            "exit;",
            buf = in(reg) core::ptr::addr_of!(buf),
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_add_const_3regs_2if
extern "C" fn check_add_const_3regs_2if() {
    unsafe {
        core::arch::asm!(
            "r6 = {buf};",
            "r7 = {buf};",
            "r8 = {buf};",
            "call 5;",
            "if r0 < 2 goto 1f;",
            "r1 = r0;",
            "r2 = r0;",
            "r1 += 1;",
            "r2 += 2;",
            "if r2 > 11 goto 1f;",
            "if r0 s< 0 goto 1f;",
            "r6 += r0;",
            "r7 += r1;",
            "r8 += r2;",
            "*(u8 *)(r6 +0) = r0;",
            "*(u8 *)(r7 -1) = r0;",
            "*(u8 *)(r8 -1) = r0;",
            "1:",
            "exit;",
            buf = in(reg) core::ptr::addr_of!(buf),
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_add_const_regsafe_off
extern "C" fn check_add_const_regsafe_off() {
    unsafe {
        core::arch::asm!(
            "r8 = {buf};",
            "call 5;",
            "r6 = r0;",
            "call 5;",
            "r7 = r0;",
            "call 5;",
            "r1 = r0;",
            "if r6 > r7 goto 1f;",
            "r1 += 1;",
            "goto 2f;",
            "1:",
            "r1 += 100;",
            "goto +0;",
            "2:",
            "if r0 > 8 goto 3f;",
            "r8 += r1;",
            "*(u8 *)(r8 +0) = r0;",
            "3:",
            "exit;",
            buf = in(reg) core::ptr::addr_of!(buf),
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
}

include!("hand/verifier_iterating_callbacks.rs");

bpf_object!("GPL");
