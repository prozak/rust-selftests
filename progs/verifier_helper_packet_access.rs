// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_helper_packet_access.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_helper_packet_access` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: test1_valid_packet_ptr_range packet_test2_unchecked_packet_ptr to_packet_test3_variable_add packet_ptr_with_bad_range_1 ptr_with_too_short_range_1 cls_valid_packet_ptr_range test7_cls_unchecked_packet_ptr packet_test8_cls_variable_add packet_ptr_with_bad_range_2 ptr_with_too_short_range_2 test11_cls_unsuitable_helper_1 test12_cls_unsuitable_helper_2 packet_test13_cls_helper_ok test14_cls_helper_ok_sub test15_cls_helper_fail_sub cls_helper_fail_range_1 cls_helper_fail_range_2 cls_helper_fail_range_3 test19_cls_helper_range_zero test20_pkt_end_as_input to_packet_test21_wrong_reg

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    test1_valid_packet_ptr_range:
        __description("helper access to packet: test1, valid packet_ptr range"),
        __success,
        __retval("0");
    packet_test2_unchecked_packet_ptr:
        __description("helper access to packet: test2, unchecked packet_ptr"),
        __failure,
        __msg("invalid access to packet");
    to_packet_test3_variable_add:
        __description("helper access to packet: test3, variable add"),
        __success,
        __retval("0");
    packet_ptr_with_bad_range_1:
        __description("helper access to packet: test4, packet_ptr with bad range"),
        __failure,
        __msg("invalid access to packet");
    ptr_with_too_short_range_1:
        __description("helper access to packet: test5, packet_ptr with too short range"),
        __failure,
        __msg("invalid access to packet");
    cls_valid_packet_ptr_range:
        __description("helper access to packet: test6, cls valid packet_ptr range"),
        __success,
        __retval("0");
    test7_cls_unchecked_packet_ptr:
        __description("helper access to packet: test7, cls unchecked packet_ptr"),
        __failure,
        __msg("invalid access to packet");
    packet_test8_cls_variable_add:
        __description("helper access to packet: test8, cls variable add"),
        __success,
        __retval("0");
    packet_ptr_with_bad_range_2:
        __description("helper access to packet: test9, cls packet_ptr with bad range"),
        __failure,
        __msg("invalid access to packet");
    ptr_with_too_short_range_2:
        __description("helper access to packet: test10, cls packet_ptr with too short range"),
        __failure,
        __msg("invalid access to packet");
    test11_cls_unsuitable_helper_1:
        __description("helper access to packet: test11, cls unsuitable helper 1"),
        __failure,
        __msg("function access to the packet");
    test12_cls_unsuitable_helper_2:
        __description("helper access to packet: test12, cls unsuitable helper 2"),
        __failure,
        __msg("function access to the packet");
    packet_test13_cls_helper_ok:
        __description("helper access to packet: test13, cls helper ok"),
        __success,
        __retval("0");
    test14_cls_helper_ok_sub:
        __description("helper access to packet: test14, cls helper ok sub"),
        __success,
        __retval("0");
    test15_cls_helper_fail_sub:
        __description("helper access to packet: test15, cls helper fail sub"),
        __failure,
        __msg("R1 min value is negative");
    cls_helper_fail_range_1:
        __description("helper access to packet: test16, cls helper fail range 1"),
        __failure,
        __msg("invalid access to packet");
    cls_helper_fail_range_2:
        __description("helper access to packet: test17, cls helper fail range 2"),
        __failure,
        __msg("R2 min value is negative");
    cls_helper_fail_range_3:
        __description("helper access to packet: test18, cls helper fail range 3"),
        __failure,
        __msg("R2 min value is negative");
    test19_cls_helper_range_zero:
        __description("helper access to packet: test19, cls helper range zero"),
        __success,
        __retval("0");
    test20_pkt_end_as_input:
        __description("helper access to packet: test20, pkt end as input"),
        __failure,
        __msg("R1 type=pkt_end expected=fp");
    to_packet_test21_wrong_reg:
        __description("helper access to packet: test21, wrong reg"),
        __failure,
        __msg("invalid access to packet");
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test1_valid_packet_ptr_range
extern "C" fn test1_valid_packet_ptr_range() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 > r3 goto l0_0;",
            "r1 = {map_hash_8b} ll;",
            "r3 = r2;",
            "r4 = 0;",
            "call 2;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_test2_unchecked_packet_ptr
extern "C" fn packet_test2_unchecked_packet_ptr() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_packet_test3_variable_add
extern "C" fn to_packet_test3_variable_add() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r4 = r2;",
            "r4 += 8;",
            "if r4 > r3 goto l0_1;",
            "r5 = *(u8*)(r2 + 0);",
            "r4 = r2;",
            "r4 += r5;",
            "r5 = r4;",
            "r5 += 8;",
            "if r5 > r3 goto l0_1;",
            "r1 = {map_hash_8b} ll;",
            "r2 = r4;",
            "call 1;",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_ptr_with_bad_range_1
extern "C" fn packet_ptr_with_bad_range_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r4 = r2;",
            "r4 += 4;",
            "if r4 > r3 goto l0_2;",
            "r0 = 0;",
            "exit;",
            "l0_2:",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_with_too_short_range_1
extern "C" fn ptr_with_too_short_range_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r2 += 1;",
            "r4 = r2;",
            "r4 += 7;",
            "if r4 > r3 goto l0_3;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: cls_valid_packet_ptr_range
extern "C" fn cls_valid_packet_ptr_range() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 > r3 goto l0_4;",
            "r1 = {map_hash_8b} ll;",
            "r3 = r2;",
            "r4 = 0;",
            "call 2;",
            "l0_4:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test7_cls_unchecked_packet_ptr
extern "C" fn test7_cls_unchecked_packet_ptr() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_test8_cls_variable_add
extern "C" fn packet_test8_cls_variable_add() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r4 = r2;",
            "r4 += 8;",
            "if r4 > r3 goto l0_5;",
            "r5 = *(u8*)(r2 + 0);",
            "r4 = r2;",
            "r4 += r5;",
            "r5 = r4;",
            "r5 += 8;",
            "if r5 > r3 goto l0_5;",
            "r1 = {map_hash_8b} ll;",
            "r2 = r4;",
            "call 1;",
            "l0_5:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_ptr_with_bad_range_2
extern "C" fn packet_ptr_with_bad_range_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r4 = r2;",
            "r4 += 4;",
            "if r4 > r3 goto l0_6;",
            "r0 = 0;",
            "exit;",
            "l0_6:",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_with_too_short_range_2
extern "C" fn ptr_with_too_short_range_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r2 += 1;",
            "r4 = r2;",
            "r4 += 7;",
            "if r4 > r3 goto l0_7;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "l0_7:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test11_cls_unsuitable_helper_1
extern "C" fn test11_cls_unsuitable_helper_1() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r6 += 1;",
            "r3 = r6;",
            "r3 += 7;",
            "if r3 > r7 goto l0_8;",
            "r2 = 0;",
            "r4 = 42;",
            "r5 = 0;",
            "call 9;",
            "l0_8:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test12_cls_unsuitable_helper_2
extern "C" fn test12_cls_unsuitable_helper_2() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r3 = r6;",
            "r6 += 8;",
            "if r6 > r7 goto l0_9;",
            "r2 = 0;",
            "r4 = 4;",
            "call 26;",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_test13_cls_helper_ok
extern "C" fn packet_test13_cls_helper_ok() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r6 += 1;",
            "r1 = r6;",
            "r1 += 7;",
            "if r1 > r7 goto l0_10;",
            "r1 = r6;",
            "r2 = 4;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_10:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test14_cls_helper_ok_sub
extern "C" fn test14_cls_helper_ok_sub() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r6 += 1;",
            "r1 = r6;",
            "r1 += 7;",
            "if r1 > r7 goto l0_11;",
            "r1 -= 4;",
            "r2 = 4;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_11:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test15_cls_helper_fail_sub
extern "C" fn test15_cls_helper_fail_sub() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r6 += 1;",
            "r1 = r6;",
            "r1 += 7;",
            "if r1 > r7 goto l0_12;",
            "r1 -= 12;",
            "r2 = 4;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_12:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: cls_helper_fail_range_1
extern "C" fn cls_helper_fail_range_1() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r6 += 1;",
            "r1 = r6;",
            "r1 += 7;",
            "if r1 > r7 goto l0_13;",
            "r1 = r6;",
            "r2 = 8;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_13:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: cls_helper_fail_range_2
extern "C" fn cls_helper_fail_range_2() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r6 += 1;",
            "r1 = r6;",
            "r1 += 7;",
            "if r1 > r7 goto l0_14;",
            "r1 = r6;",
            "r2 = -9;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_14:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: cls_helper_fail_range_3
extern "C" fn cls_helper_fail_range_3() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r6 += 1;",
            "r1 = r6;",
            "r1 += 7;",
            "if r1 > r7 goto l0_15;",
            "r1 = r6;",
            "r2 = -1;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_15:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test19_cls_helper_range_zero
extern "C" fn test19_cls_helper_range_zero() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r6 += 1;",
            "r1 = r6;",
            "r1 += 7;",
            "if r1 > r7 goto l0_16;",
            "r1 = r6;",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_16:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test20_pkt_end_as_input
extern "C" fn test20_pkt_end_as_input() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r6 += 1;",
            "r1 = r6;",
            "r1 += 7;",
            "if r1 > r7 goto l0_17;",
            "r1 = r7;",
            "r2 = 4;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_17:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_packet_test21_wrong_reg
extern "C" fn to_packet_test21_wrong_reg() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r7 = *(u32*)(r1 + 80);",
            "r6 += 1;",
            "r1 = r6;",
            "r1 += 7;",
            "if r1 > r7 goto l0_18;",
            "r2 = 4;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "r0 = 0;",
            "l0_18:",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
