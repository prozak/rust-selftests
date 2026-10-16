// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/linked_list_peek.c
// (bpf-rs-core idiom).
//
// glock and ghead are C `private(A)` statics: `__hidden` in SEC(".data.A"),
// so BTF_VAR_STATIC and the map is not mmapped by libbpf. A private Rust
// static (no #[no_mangle]) gets the same linkage (see test_spin_lock.rs);
// rust-bpf's #[btf_tag] still finds it by its debug-info name and puts C's
// __contains(node_data, l) decl tag on it. bpf_obj_new() takes node_data's
// local type id like C's bpf_obj_new(typeof(*n)).
//
// The C programs return __LINE__ to say which check failed; the constants
// below are the C file's line numbers, so the objects agree.

// BTF_TYPE_ID: node_data_id local struct node_data

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_jiffies64, bpf_spin_lock, bpf_spin_unlock};
use btf_macros::btf_tag;
use core::ffi::c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_list_head {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_list_node {
    __opaque: [u64; 3],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct node_data {
    l: bpf_list_node,
    key: i32,
}

#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut glock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:l")]
#[link_section = ".data.A"]
static mut ghead: bpf_list_head = bpf_list_head { __opaque: [0; 2] };

const NR_NODES: i32 = 16;

#[no_mangle]
static mut zero: i32 = 0;

extern "C" {
    fn node_data_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_list_push_back(head: *mut bpf_list_head, node: *mut bpf_list_node) -> i32;
    fn bpf_list_front(head: *mut bpf_list_head) -> *mut bpf_list_node;
    fn bpf_list_back(head: *mut bpf_list_head) -> *mut bpf_list_node;
}

// bpf_misc.h's `can_loop` (bpf_may_goto.h): the may_goto instruction, which
// the verifier lets the loop take only while it still has budget.
#[inline(always)]
unsafe fn can_loop() -> bool {
    let mut ret = true;
    core::arch::asm!(
        "1:",
        ".byte 0xe5",
        ".byte 0",
        ".long (({0} - 1b - 8) / 8) & 0xffff",
        ".short 0",
        label { ret = false; },
    );
    ret
}

// list_entry(ptr, struct node_data, l)
#[inline(always)]
unsafe fn list_entry(l_n: *mut bpf_list_node) -> *mut node_data {
    (l_n as *mut u8).sub(core::mem::offset_of!(node_data, l)) as *mut node_data
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn list_peek(_ctx: *const c_void) -> i64 {
    let mut err: i64 = 0;

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!(glock));
        let l_n = bpf_list_front(core::ptr::addr_of_mut!(ghead));
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
        if !l_n.is_null() {
            return 35;
        }

        bpf_spin_lock(core::ptr::addr_of_mut!(glock));
        let l_n = bpf_list_back(core::ptr::addr_of_mut!(ghead));
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
        if !l_n.is_null() {
            return 41;
        }

        let mut i = zero;
        while i < NR_NODES && can_loop() {
            let n = bpf_obj_new(node_data_id()) as *mut node_data;
            if n.is_null() {
                return 46;
            }
            (*n).key = i;
            bpf_spin_lock(core::ptr::addr_of_mut!(glock));
            bpf_list_push_back(core::ptr::addr_of_mut!(ghead), core::ptr::addr_of_mut!((*n).l));
            bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
            i += 1;
        }

        bpf_spin_lock(core::ptr::addr_of_mut!(glock));

        'done: {
            let l_n = bpf_list_front(core::ptr::addr_of_mut!(ghead));
            if l_n.is_null() {
                err = 57;
                break 'done;
            }

            let n = list_entry(l_n);
            if (*n).key != 0 {
                err = 63;
                break 'done;
            }

            let l_n = bpf_list_back(core::ptr::addr_of_mut!(ghead));
            if l_n.is_null() {
                err = 69;
                break 'done;
            }

            let n = list_entry(l_n);
            if (*n).key != NR_NODES - 1 {
                err = 75;
                break 'done;
            }
        }

        bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
    }
    err
}

// TEST_FB(op, dolock): peek with and without the lock held; the unlocked
// ones are __failure programs.
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_front_spinlock_true(_ctx: *const c_void) -> i64 {
    let mut jiffies: u64 = 0;
    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!(glock));
        let l_n = bpf_list_front(core::ptr::addr_of_mut!(ghead));
        if !l_n.is_null() {
            jiffies = bpf_jiffies64();
        }
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
    }
    (jiffies != 0) as i64
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_back_spinlock_true(_ctx: *const c_void) -> i64 {
    let mut jiffies: u64 = 0;
    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!(glock));
        let l_n = bpf_list_back(core::ptr::addr_of_mut!(ghead));
        if !l_n.is_null() {
            jiffies = bpf_jiffies64();
        }
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
    }
    (jiffies != 0) as i64
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_front_spinlock_false(_ctx: *const c_void) -> i64 {
    let mut jiffies: u64 = 0;
    unsafe {
        let l_n = bpf_list_front(core::ptr::addr_of_mut!(ghead));
        if !l_n.is_null() {
            jiffies = bpf_jiffies64();
        }
    }
    (jiffies != 0) as i64
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_back_spinlock_false(_ctx: *const c_void) -> i64 {
    let mut jiffies: u64 = 0;
    unsafe {
        let l_n = bpf_list_back(core::ptr::addr_of_mut!(ghead));
        if !l_n.is_null() {
            jiffies = bpf_jiffies64();
        }
    }
    (jiffies != 0) as i64
}

bpf_object!("GPL");
bpf_rs_core::test_tags! {
    list_peek: __retval("0");
    test_front_spinlock_true: __failure, __msg("call bpf_list_{{(front|back).+}}; R0{{(_w)?}}=ptr_or_null_node_data(id={{[0-9]+}},non_own_ref");
    test_back_spinlock_true: __failure, __msg("call bpf_list_{{(front|back).+}}; R0{{(_w)?}}=ptr_or_null_node_data(id={{[0-9]+}},non_own_ref");
    test_front_spinlock_false: __failure, __msg("bpf_spin_lock at off=0 must be held for bpf_list_head");
    test_back_spinlock_false: __failure, __msg("bpf_spin_lock at off=0 must be held for bpf_list_head");
}
