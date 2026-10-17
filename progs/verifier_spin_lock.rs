// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_spin_lock.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_spin_lock.rs
// (include!d below): bpf_loop_inside_locked_region.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_spin_lock` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: spin_lock_test1_success lock_test2_direct_ld_st lock_test3_direct_ld_st lock_test4_direct_ld_st call_within_a_locked_region spin_lock_test6_missing_unlock lock_test7_unlock_without_lock spin_lock_test8_double_lock spin_lock_test9_different_lock lock_in_subprog_without_unlock lock_in_subprog_without_unlock__1 test11_ld_abs_under_lock reg_id_for_map_value check_ids_similar_id_mappings bpf_loop_inside_locked_region

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    spin_lock_test1_success:
        __description("spin_lock: test1 success"),
        __success,
        __failure_unpriv,
        __msg_unpriv(""),
        __retval("0");
    lock_test2_direct_ld_st:
        __description("spin_lock: test2 direct ld/st"),
        __failure,
        __msg("cannot be accessed directly"),
        __failure_unpriv,
        __msg_unpriv("");
    lock_test3_direct_ld_st:
        __description("spin_lock: test3 direct ld/st"),
        __failure,
        __msg("cannot be accessed directly"),
        __failure_unpriv,
        __msg_unpriv(""),
        __flag("BPF_F_ANY_ALIGNMENT");
    lock_test4_direct_ld_st:
        __description("spin_lock: test4 direct ld/st"),
        __failure,
        __msg("cannot be accessed directly"),
        __failure_unpriv,
        __msg_unpriv(""),
        __flag("BPF_F_ANY_ALIGNMENT");
    call_within_a_locked_region:
        __description("spin_lock: test5 call within a locked region"),
        __failure,
        __msg("calls are not allowed"),
        __failure_unpriv,
        __msg_unpriv("");
    spin_lock_test6_missing_unlock:
        __description("spin_lock: test6 missing unlock"),
        __failure,
        __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_spin_lock-ed region"),
        __failure_unpriv,
        __msg_unpriv("");
    lock_test7_unlock_without_lock:
        __description("spin_lock: test7 unlock without lock"),
        __failure,
        __msg("without taking a lock"),
        __failure_unpriv,
        __msg_unpriv("");
    spin_lock_test8_double_lock:
        __description("spin_lock: test8 double lock"),
        __failure,
        __msg("calls are not allowed"),
        __failure_unpriv,
        __msg_unpriv("");
    spin_lock_test9_different_lock:
        __description("spin_lock: test9 different lock"),
        __failure,
        __msg("unlock of different lock"),
        __failure_unpriv,
        __msg_unpriv("");
    lock_in_subprog_without_unlock:
        __description("spin_lock: test10 lock in subprog without unlock"),
        __success,
        __failure_unpriv,
        __msg_unpriv("");
    test11_ld_abs_under_lock:
        __description("spin_lock: test11 ld_abs under lock"),
        __failure,
        __msg("inside bpf_spin_lock");
    reg_id_for_map_value:
        __description("spin_lock: regsafe compare reg->id for map value"),
        __failure,
        __msg("bpf_spin_unlock of different lock"),
        __flag("BPF_F_TEST_STATE_FREQ");
    check_ids_similar_id_mappings:
        __description("spin_lock: regsafe() check_ids() similar id mappings"),
        __success,
        __msg("29: safe"),
        __failure_unpriv,
        __msg_unpriv(""),
        __log_level("2"),
        __retval("0"),
        __flag("BPF_F_TEST_STATE_FREQ");
    bpf_loop_inside_locked_region:
        __description("spin_lock: loop within a locked region"),
        __success,
        __failure_unpriv,
        __msg_unpriv(""),
        __retval("0");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct val {
    cnt: i32,
    l: bpf_spin_lock,
}

bpf_map! {
    map_spin_lock {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const val,
    }
}

extern "C" {
    fn bpf_iter_num_new(a0: *mut c_void, a1: i32, a2: i32) -> i32;
    fn bpf_iter_num_next(a0: *mut c_void) -> *mut c_void;
    fn bpf_iter_num_destroy(a0: *mut c_void);
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spin_lock_test1_success
extern "C" fn spin_lock_test1_success() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_0;",
            "exit;",
            "l0_0:",
            "r6 = r0;",
            "r1 = r0;",
            "r1 += 4;",
            "call 93;",
            "r1 = r6;",
            "r1 += 4;",
            "r0 = *(u32*)(r6 + 0);",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lock_test2_direct_ld_st
extern "C" fn lock_test2_direct_ld_st() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_1;",
            "exit;",
            "l0_1:",
            "r6 = r0;",
            "r1 = r0;",
            "r1 += 4;",
            "call 93;",
            "r1 = r6;",
            "r1 += 4;",
            "r0 = *(u32*)(r1 + 0);",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lock_test3_direct_ld_st
extern "C" fn lock_test3_direct_ld_st() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_2;",
            "exit;",
            "l0_2:",
            "r6 = r0;",
            "r1 = r0;",
            "r1 += 4;",
            "call 93;",
            "r1 = r6;",
            "r1 += 4;",
            "r0 = *(u32*)(r6 + 1);",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lock_test4_direct_ld_st
extern "C" fn lock_test4_direct_ld_st() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_3;",
            "exit;",
            "l0_3:",
            "r6 = r0;",
            "r1 = r0;",
            "r1 += 4;",
            "call 93;",
            "r1 = r6;",
            "r1 += 4;",
            "r0 = *(u16*)(r6 + 3);",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: call_within_a_locked_region
extern "C" fn call_within_a_locked_region() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_4;",
            "exit;",
            "l0_4:",
            "r6 = r0;",
            "r1 = r0;",
            "r1 += 4;",
            "call 93;",
            "call 7;",
            "r1 = r6;",
            "r1 += 4;",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spin_lock_test6_missing_unlock
extern "C" fn spin_lock_test6_missing_unlock() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_5;",
            "exit;",
            "l0_5:",
            "r6 = r0;",
            "r1 = r0;",
            "r1 += 4;",
            "call 93;",
            "r1 = r6;",
            "r1 += 4;",
            "r0 = *(u32*)(r6 + 0);",
            "if r0 != 0 goto l1_5;",
            "call 94;",
            "l1_5:",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lock_test7_unlock_without_lock
extern "C" fn lock_test7_unlock_without_lock() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_6;",
            "exit;",
            "l0_6:",
            "r6 = r0;",
            "r1 = r0;",
            "r1 += 4;",
            "if r1 != 0 goto l1_6;",
            "call 93;",
            "l1_6:",
            "r1 = r6;",
            "r1 += 4;",
            "r0 = *(u32*)(r6 + 0);",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spin_lock_test8_double_lock
extern "C" fn spin_lock_test8_double_lock() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_7;",
            "exit;",
            "l0_7:",
            "r6 = r0;",
            "r1 = r0;",
            "r1 += 4;",
            "call 93;",
            "r1 = r6;",
            "r1 += 4;",
            "call 93;",
            "r1 = r6;",
            "r1 += 4;",
            "r0 = *(u32*)(r6 + 0);",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spin_lock_test9_different_lock
extern "C" fn spin_lock_test9_different_lock() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_8;",
            "exit;",
            "l0_8:",
            "r6 = r0;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l1_8;",
            "exit;",
            "l1_8:",
            "r7 = r0;",
            "r1 = r6;",
            "r1 += 4;",
            "call 93;",
            "r1 = r7;",
            "r1 += 4;",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lock_in_subprog_without_unlock
extern "C" fn lock_in_subprog_without_unlock() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_9;",
            "exit;",
            "l0_9:",
            "r6 = r0;",
            "r1 = r0;",
            "r1 += 4;",
            "call {lock_in_subprog_without_unlock__1};",
            "r1 = r6;",
            "r1 += 4;",
            "call 94;",
            "r0 = 1;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            lock_in_subprog_without_unlock__1 = sym lock_in_subprog_without_unlock__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: lock_in_subprog_without_unlock__1
extern "C" fn lock_in_subprog_without_unlock__1() {
    unsafe {
        core::arch::asm!(
            "call 93;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test11_ld_abs_under_lock
extern "C" fn test11_ld_abs_under_lock() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 != 0 goto l0_10;",
            "exit;",
            "l0_10:",
            "r7 = r0;",
            "r1 = r0;",
            "r1 += 4;",
            "call 93;",
            "r0 = *(u8*)skb[0];",
            "r1 = r7;",
            "r1 += 4;",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reg_id_for_map_value
extern "C" fn reg_id_for_map_value() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r6 = *(u32*)(r6 + 8);",
            "r1 = {map_spin_lock} ll;",
            "r9 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 4) = r2;",
            "r2 = r10;",
            "r2 += -4;",
            "call 1;",
            "if r0 != 0 goto l0_11;",
            "exit;",
            "l0_11:",
            "r7 = r0;",
            "r1 = r9;",
            "r2 = r10;",
            "r2 += -4;",
            "call 1;",
            "if r0 != 0 goto l1_11;",
            "exit;",
            "l1_11:",
            "r8 = r0;",
            "r1 = r7;",
            "r1 += 4;",
            "call 93;",
            "if r6 == 0 goto l2_11;",
            "goto l3_11;",
            "l2_11:",
            "r7 = r8;",
            "l3_11:",
            "r1 = r7;",
            "r1 += 4;",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_ids_similar_id_mappings
extern "C" fn check_ids_similar_id_mappings() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 == 0 goto l0_12;",
            "r9 = r0;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 == 0 goto l1_12;",
            "r8 = r0;",
            "call 5;",
            "r7 = r0;",
            "call 5;",
            "r6 = r0;",
            "if r6 > r7 goto l2_12;",
            "r1 = r8;",
            "r1 += 4;",
            "call 93;",
            "r9 = r8;",
            "goto l3_12;",
            "l2_12:",
            "r1 = r9;",
            "r1 += 4;",
            "call 93;",
            "l3_12:",
            "r1 = r9;",
            "r1 += 4;",
            "call 94;",
            "l0_12:",
            "r0 = 0;",
            "l1_12:",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

include!("hand/verifier_spin_lock.rs");

bpf_object!("GPL");
