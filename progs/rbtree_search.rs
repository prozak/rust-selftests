// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/rbtree_search.c
// (bpf-rs-core idiom).
//
// glock0/groot0 and glock1/groot1 are C `private(A)`/`private(B)` statics:
// `__hidden` in SEC(".data.A"/".data.B"), so BTF_VAR_STATIC and the maps are
// not mmapped by libbpf. A private Rust static (no #[no_mangle]) gets the
// same linkage (see test_spin_lock.rs); rust-bpf's #[btf_tag] still finds
// it by its debug-info name and puts C's __contains(node_data, rN) decl tag
// on it. bpf_obj_new() takes node_data's local type id like C's
// bpf_obj_new(typeof(*n)).
//
// rbtree_search returns __LINE__ to say which check failed; the constants
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
#[repr(C, align(4))]
struct bpf_refcount {
    __opaque: [u32; 1],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_rb_root {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_rb_node {
    __opaque: [u64; 4],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct node_data {
    r#ref: bpf_refcount,
    r0: bpf_rb_node,
    r1: bpf_rb_node,
    key0: i32,
    key1: i32,
}

#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut glock0: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:r0")]
#[link_section = ".data.A"]
static mut groot0: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

#[allow(non_upper_case_globals)]
#[link_section = ".data.B"]
static mut glock1: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:r1")]
#[link_section = ".data.B"]
static mut groot1: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

const NR_NODES: i32 = 16;

#[no_mangle]
static mut zero: i32 = 0;

extern "C" {
    fn node_data_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_refcount_acquire(obj: *mut c_void) -> *mut c_void;
    fn bpf_rbtree_add(
        root: *mut bpf_rb_root,
        node: *mut bpf_rb_node,
        less: extern "C" fn(*mut bpf_rb_node, *const bpf_rb_node) -> bool,
    ) -> i32;
    fn bpf_rbtree_root(root: *mut bpf_rb_root) -> *mut bpf_rb_node;
    fn bpf_rbtree_left(root: *mut bpf_rb_root, node: *mut bpf_rb_node) -> *mut bpf_rb_node;
    fn bpf_rbtree_right(root: *mut bpf_rb_root, node: *mut bpf_rb_node) -> *mut bpf_rb_node;
    fn bpf_rbtree_remove(root: *mut bpf_rb_root, node: *mut bpf_rb_node) -> *mut bpf_rb_node;
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

// rb_entry(ptr, struct node_data, r0) / r1
#[inline(always)]
unsafe fn entry_r0(n: *mut bpf_rb_node) -> *mut node_data {
    (n as *mut u8).sub(core::mem::offset_of!(node_data, r0)) as *mut node_data
}

#[inline(always)]
unsafe fn entry_r1(n: *mut bpf_rb_node) -> *mut node_data {
    (n as *mut u8).sub(core::mem::offset_of!(node_data, r1)) as *mut node_data
}

extern "C" fn less0(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let node_a = entry_r0(a);
        let node_b = entry_r0(b as *mut bpf_rb_node);
        (*node_a).key0 < (*node_b).key0
    }
}

extern "C" fn less1(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let node_a = entry_r1(a);
        let node_b = entry_r1(b as *mut bpf_rb_node);
        (*node_a).key1 < (*node_b).key1
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn rbtree_search(_ctx: *const c_void) -> i64 {
    let mut gc_ns: [*mut bpf_rb_node; NR_NODES as usize] = [core::ptr::null_mut(); NR_NODES as usize];
    let lookup_key: i64 = (NR_NODES / 2) as i64;
    let mut nr_gc: i32 = 0;

    unsafe {
        let mut i = zero;
        while i < NR_NODES && can_loop() {
            let n = bpf_obj_new(node_data_id()) as *mut node_data;
            if n.is_null() {
                return 63;
            }

            let m = bpf_refcount_acquire(n.cast()) as *mut node_data;

            (*n).key0 = i;
            (*m).key1 = i;

            bpf_spin_lock(core::ptr::addr_of_mut!(glock0));
            bpf_rbtree_add(core::ptr::addr_of_mut!(groot0), core::ptr::addr_of_mut!((*n).r0), less0);
            bpf_spin_unlock(core::ptr::addr_of_mut!(glock0));

            bpf_spin_lock(core::ptr::addr_of_mut!(glock1));
            bpf_rbtree_add(core::ptr::addr_of_mut!(groot1), core::ptr::addr_of_mut!((*m).r1), less1);
            bpf_spin_unlock(core::ptr::addr_of_mut!(glock1));
            i += 1;
        }

        let mut n: *mut node_data = core::ptr::null_mut();
        bpf_spin_lock(core::ptr::addr_of_mut!(glock0));
        let mut rb_n = bpf_rbtree_root(core::ptr::addr_of_mut!(groot0));
        while can_loop() {
            if rb_n.is_null() {
                bpf_spin_unlock(core::ptr::addr_of_mut!(glock0));
                return 85;
            }

            n = entry_r0(rb_n);
            if lookup_key == (*n).key0 as i64 {
                break;
            }
            if nr_gc < NR_NODES {
                *gc_ns.get_unchecked_mut(nr_gc as usize) = rb_n;
                nr_gc += 1;
            }
            if lookup_key < (*n).key0 as i64 {
                rb_n = bpf_rbtree_left(core::ptr::addr_of_mut!(groot0), rb_n);
            } else {
                rb_n = bpf_rbtree_right(core::ptr::addr_of_mut!(groot0), rb_n);
            }
        }

        if n.is_null() || lookup_key != (*n).key0 as i64 {
            bpf_spin_unlock(core::ptr::addr_of_mut!(glock0));
            return 101;
        }

        let mut i: i32 = 0;
        while i < nr_gc {
            let rb_n = *gc_ns.get_unchecked(i as usize);
            *gc_ns.get_unchecked_mut(i as usize) =
                bpf_rbtree_remove(core::ptr::addr_of_mut!(groot0), rb_n);
            i += 1;
        }

        let m = bpf_refcount_acquire(n.cast()) as *mut node_data;
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock0));

        let mut i: i32 = 0;
        while i < nr_gc {
            let rb_n = *gc_ns.get_unchecked(i as usize);
            if !rb_n.is_null() {
                let n = entry_r0(rb_n);
                bpf_obj_drop(n.cast());
            }
            i += 1;
        }

        if m.is_null() {
            return 121;
        }

        bpf_spin_lock(core::ptr::addr_of_mut!(glock1));
        let rb_m = bpf_rbtree_remove(core::ptr::addr_of_mut!(groot1), core::ptr::addr_of_mut!((*m).r1));
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock1));
        bpf_obj_drop(m.cast());
        if rb_m.is_null() {
            return 128;
        }
        bpf_obj_drop(entry_r1(rb_m).cast());
    }

    0
}

// TEST_ROOT(dolock)
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_root_spinlock_true(_ctx: *const c_void) -> i64 {
    let mut jiffies: u64 = 0;
    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!(glock0));
        let rb_n = bpf_rbtree_root(core::ptr::addr_of_mut!(groot0));
        if !rb_n.is_null() {
            jiffies = bpf_jiffies64();
        }
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock0));
    }
    (jiffies != 0) as i64
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_root_spinlock_false(_ctx: *const c_void) -> i64 {
    let mut jiffies: u64 = 0;
    unsafe {
        let rb_n = bpf_rbtree_root(core::ptr::addr_of_mut!(groot0));
        if !rb_n.is_null() {
            jiffies = bpf_jiffies64();
        }
    }
    (jiffies != 0) as i64
}

// TEST_LR(op, dolock): the shared prologue takes a reference to the root
// node under the lock, then peeks at its child with or without the lock.
#[inline(always)]
unsafe fn test_lr_prologue() -> *mut node_data {
    bpf_spin_lock(core::ptr::addr_of_mut!(glock0));
    let rb_n = bpf_rbtree_root(core::ptr::addr_of_mut!(groot0));
    if rb_n.is_null() {
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock0));
        return core::ptr::null_mut();
    }
    let n = entry_r0(rb_n);
    let n = bpf_refcount_acquire(n.cast()) as *mut node_data;
    bpf_spin_unlock(core::ptr::addr_of_mut!(glock0));
    n
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_left_spinlock_true(_ctx: *const c_void) -> i64 {
    let mut jiffies: u64 = 0;
    unsafe {
        let n = test_lr_prologue();
        if n.is_null() {
            return 1;
        }

        bpf_spin_lock(core::ptr::addr_of_mut!(glock0));
        let rb_n = bpf_rbtree_left(core::ptr::addr_of_mut!(groot0), core::ptr::addr_of_mut!((*n).r0));
        if !rb_n.is_null() {
            jiffies = bpf_jiffies64();
        }
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock0));
    }
    (jiffies != 0) as i64
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_right_spinlock_true(_ctx: *const c_void) -> i64 {
    let mut jiffies: u64 = 0;
    unsafe {
        let n = test_lr_prologue();
        if n.is_null() {
            return 1;
        }

        bpf_spin_lock(core::ptr::addr_of_mut!(glock0));
        let rb_n = bpf_rbtree_right(core::ptr::addr_of_mut!(groot0), core::ptr::addr_of_mut!((*n).r0));
        if !rb_n.is_null() {
            jiffies = bpf_jiffies64();
        }
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock0));
    }
    (jiffies != 0) as i64
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_left_spinlock_false(_ctx: *const c_void) -> i64 {
    let mut jiffies: u64 = 0;
    unsafe {
        let n = test_lr_prologue();
        if n.is_null() {
            return 1;
        }

        let rb_n = bpf_rbtree_left(core::ptr::addr_of_mut!(groot0), core::ptr::addr_of_mut!((*n).r0));
        if !rb_n.is_null() {
            jiffies = bpf_jiffies64();
        }
    }
    (jiffies != 0) as i64
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_right_spinlock_false(_ctx: *const c_void) -> i64 {
    let mut jiffies: u64 = 0;
    unsafe {
        let n = test_lr_prologue();
        if n.is_null() {
            return 1;
        }

        let rb_n = bpf_rbtree_right(core::ptr::addr_of_mut!(groot0), core::ptr::addr_of_mut!((*n).r0));
        if !rb_n.is_null() {
            jiffies = bpf_jiffies64();
        }
    }
    (jiffies != 0) as i64
}

bpf_object!("GPL");
bpf_rs_core::test_tags! {
    rbtree_search: __retval("0");
    test_root_spinlock_true: __failure, __msg("call bpf_rbtree_root{{.+}}; R0{{(_w)?}}=rcu_ptr_or_null_node_data(id={{[0-9]+}},non_own_ref");
    test_left_spinlock_true: __failure, __msg("call bpf_rbtree_{{(left|right).+}}; R0{{(_w)?}}=rcu_ptr_or_null_node_data(id={{[0-9]+}},non_own_ref");
    test_right_spinlock_true: __failure, __msg("call bpf_rbtree_{{(left|right).+}}; R0{{(_w)?}}=rcu_ptr_or_null_node_data(id={{[0-9]+}},non_own_ref");
    test_root_spinlock_false: __failure, __msg("bpf_spin_lock at off=0 must be held for bpf_rb_root");
    test_left_spinlock_false: __failure, __msg("bpf_spin_lock at off=0 must be held for bpf_rb_root");
    test_right_spinlock_false: __failure, __msg("bpf_spin_lock at off=0 must be held for bpf_rb_root");
}
