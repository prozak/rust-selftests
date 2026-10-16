// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/refcounted_kptr.c
// (bpf-rs-core idiom).
//
// The private(A/B/C/kptr_ref) statics are C `__hidden` variables in
// `.bss.<name>`; a private Rust static (no #[no_mangle]) gets the same
// linkage, and scripts/private_sections.py lays each section out as the C
// object has it. clang does NOT emit them in declaration order but in the
// order the code first refers to them (`llvm-readelf -s
// refcounted_kptr.bpf.o`: head 0, root 16, lock 32); the statics below are
// declared in that order too, and the two __failure programs expect the
// lock "at off=32".
//
// bpf_list_empty/is_first/is_last return `bool`. rustc trusts an extern
// `-> bool` to come back zero-extended and tests all of w0, while clang
// masks it with `w0 &= 1` (issue #36). The kernel's bpf_list_empty() really
// does leave the list pointer in the upper bits of %rax (`mov (%rdi),%rax;
// cmp %rax,%rdi; sete %al`), so an unmasked translation fails
// list_empty_test at runtime. Until rust-bpf masks kfunc returns like clang
// the three are declared `-> u32` and masked here, which compiles to C's
// `w0 &= 1`.
//
// The four C macro families (INSERT_READ_BOTH x2, INSERT_DOUBLE_READ_AND_DEL,
// INSERT_STASH_READ) are macro_rules! that keep C's program names.
// map_value.node is a __kptr (btf_type_tags!); the __contains tags are
// rust-bpf's #[btf_tag] decl tags.

// BTF_TYPE_ID: node_data_id local struct node_data
// BTF_TYPE_ID: node_acquire_id local struct node_acquire

use bpf_rs_core::helpers::{
    bpf_kptr_xchg, bpf_map_lookup_elem, bpf_map_lookup_percpu_elem, bpf_probe_read_kernel,
    bpf_spin_lock, bpf_spin_unlock,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, btf_type_tags, test_tags};
use btf_macros::btf_tag;
use core::ffi::c_void;
use core::ptr::{addr_of_mut, null_mut};

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
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
#[repr(C, align(4))]
struct bpf_refcount {
    __opaque: [u32; 1],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct node_data {
    key: i64,
    list_data: i64,
    r: bpf_rb_node,
    l: bpf_list_node,
    r#ref: bpf_refcount,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_value {
    node: *mut node_data,
}

#[link_section = ".maps"]
#[no_mangle]
static stashed_nodes: BpfMap<i32, map_value, { maps::ARRAY }, 2> = BpfMap::new();

#[allow(non_camel_case_types)]
#[repr(C)]
struct node_acquire {
    key: i64,
    data: i64,
    node: bpf_rb_node,
    refcount: bpf_refcount,
}

// private(A): C declares lock, root, head; clang lays them out head, root,
// lock (first use: __insert_in_tree_and_list(&head, &root, &lock)). The
// helpers' parameters are head_/root_/lock_: rustc does not let a
// parameter share a static's name.
#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:l")]
#[link_section = ".bss.A"]
static mut head: bpf_list_head = bpf_list_head { __opaque: [0; 2] };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:r")]
#[link_section = ".bss.A"]
static mut root: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

#[allow(non_upper_case_globals)]
#[link_section = ".bss.A"]
static mut lock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[link_section = ".bss.B"]
static mut alock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_acquire:node")]
#[link_section = ".bss.B"]
static mut aroot: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

#[allow(non_upper_case_globals)]
#[link_section = ".bss.C"]
static mut block: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:r")]
#[link_section = ".bss.C"]
static mut broot: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

extern "C" {
    fn node_data_id() -> u64;
    fn node_acquire_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_refcount_acquire(obj: *mut c_void) -> *mut c_void;
    fn bpf_rbtree_add(
        root: *mut bpf_rb_root,
        node: *mut bpf_rb_node,
        less: extern "C" fn(*mut bpf_rb_node, *const bpf_rb_node) -> bool,
    ) -> i32;
    fn bpf_rbtree_first(root: *mut bpf_rb_root) -> *mut bpf_rb_node;
    fn bpf_rbtree_remove(root: *mut bpf_rb_root, node: *mut bpf_rb_node) -> *mut bpf_rb_node;
    fn bpf_list_push_front(head: *mut bpf_list_head, node: *mut bpf_list_node) -> i32;
    fn bpf_list_push_back(head: *mut bpf_list_head, node: *mut bpf_list_node) -> i32;
    fn bpf_list_pop_front(head: *mut bpf_list_head) -> *mut bpf_list_node;
    fn bpf_list_front(head: *mut bpf_list_head) -> *mut bpf_list_node;
    fn bpf_list_back(head: *mut bpf_list_head) -> *mut bpf_list_node;
    fn bpf_list_del(head: *mut bpf_list_head, node: *mut bpf_list_node) -> *mut bpf_list_node;
    fn bpf_list_add(
        head: *mut bpf_list_head,
        new: *mut bpf_list_node,
        prev: *mut bpf_list_node,
    ) -> i32;
    // bool in the kernel; see the header comment (#36)
    #[link_name = "bpf_list_empty"]
    fn bpf_list_empty_w(head: *mut bpf_list_head) -> u32;
    #[link_name = "bpf_list_is_first"]
    fn bpf_list_is_first_w(head: *mut bpf_list_head, node: *mut bpf_list_node) -> u32;
    #[link_name = "bpf_list_is_last"]
    fn bpf_list_is_last_w(head: *mut bpf_list_head, node: *mut bpf_list_node) -> u32;
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

#[inline(always)]
unsafe fn bpf_list_empty(head_: *mut bpf_list_head) -> bool {
    bpf_list_empty_w(head_) & 1 != 0
}

#[inline(always)]
unsafe fn bpf_list_is_first(head_: *mut bpf_list_head, node: *mut bpf_list_node) -> bool {
    bpf_list_is_first_w(head_, node) & 1 != 0
}

#[inline(always)]
unsafe fn bpf_list_is_last(head_: *mut bpf_list_head, node: *mut bpf_list_node) -> bool {
    bpf_list_is_last_w(head_, node) & 1 != 0
}

// container_of(ptr, struct node_data, r) / l
#[inline(always)]
unsafe fn entry_r(n: *mut bpf_rb_node) -> *mut node_data {
    (n as *mut u8).sub(core::mem::offset_of!(node_data, r)) as *mut node_data
}

#[inline(always)]
unsafe fn entry_l(n: *mut bpf_list_node) -> *mut node_data {
    (n as *mut u8).sub(core::mem::offset_of!(node_data, l)) as *mut node_data
}

// container_of(ptr, struct node_acquire, node)
#[inline(always)]
unsafe fn entry_a(n: *mut bpf_rb_node) -> *mut node_acquire {
    (n as *mut u8).sub(core::mem::offset_of!(node_acquire, node)) as *mut node_acquire
}

extern "C" fn less(node_a: *mut bpf_rb_node, node_b: *const bpf_rb_node) -> bool {
    unsafe {
        let a = entry_r(node_a);
        let b = entry_r(node_b as *mut bpf_rb_node);

        (*a).key < (*b).key
    }
}

extern "C" fn less_a(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let node_a = entry_a(a);
        let node_b = entry_a(b as *mut bpf_rb_node);

        (*node_a).key < (*node_b).key
    }
}

unsafe fn __insert_in_tree_and_list(
    head_: *mut bpf_list_head,
    root_: *mut bpf_rb_root,
    lock_: *mut bpf_spin_lock,
) -> i64 {
    let n = bpf_obj_new(node_data_id()) as *mut node_data;
    if n.is_null() {
        return -1;
    }

    let m = bpf_refcount_acquire(n.cast()) as *mut node_data;
    (*m).key = 123;
    (*m).list_data = 456;

    bpf_spin_lock(lock_);
    if bpf_rbtree_add(root_, addr_of_mut!((*n).r), less) != 0 {
        /* Failure to insert - unexpected */
        bpf_spin_unlock(lock_);
        bpf_obj_drop(m.cast());
        return -2;
    }
    bpf_spin_unlock(lock_);

    bpf_spin_lock(lock_);
    if bpf_list_push_front(head_, addr_of_mut!((*m).l)) != 0 {
        /* Failure to insert - unexpected */
        bpf_spin_unlock(lock_);
        return -3;
    }
    bpf_spin_unlock(lock_);
    0
}

unsafe fn __stash_map_insert_tree(
    idx: i32,
    val: i32,
    root_: *mut bpf_rb_root,
    lock_: *mut bpf_spin_lock,
) -> i64 {
    let mapval = bpf_map_lookup_elem(&stashed_nodes, &idx) as *mut map_value;
    if mapval.is_null() {
        return -1;
    }

    let n = bpf_obj_new(node_data_id()) as *mut node_data;
    if n.is_null() {
        return -2;
    }

    (*n).key = val as i64;
    let m = bpf_refcount_acquire(n.cast()) as *mut node_data;

    let n = bpf_kptr_xchg(addr_of_mut!((*mapval).node).cast(), n.cast()) as *mut node_data;
    if !n.is_null() {
        bpf_obj_drop(n.cast());
        bpf_obj_drop(m.cast());
        return -3;
    }

    bpf_spin_lock(lock_);
    if bpf_rbtree_add(root_, addr_of_mut!((*m).r), less) != 0 {
        /* Failure to insert - unexpected */
        bpf_spin_unlock(lock_);
        return -4;
    }
    bpf_spin_unlock(lock_);
    0
}

unsafe fn __read_from_tree(
    root_: *mut bpf_rb_root,
    lock_: *mut bpf_spin_lock,
    remove_from_tree: bool,
) -> i64 {
    bpf_spin_lock(lock_);

    let rb = bpf_rbtree_first(root_);
    if rb.is_null() {
        bpf_spin_unlock(lock_);
        return -1;
    }

    let n = entry_r(rb);
    let res = (*n).key;

    if !remove_from_tree {
        bpf_spin_unlock(lock_);
        return res;
    }

    let rb = bpf_rbtree_remove(root_, rb);
    bpf_spin_unlock(lock_);
    if rb.is_null() {
        return -2;
    }
    let n = entry_r(rb);
    bpf_obj_drop(n.cast());
    res
}

unsafe fn __read_from_list(
    head_: *mut bpf_list_head,
    lock_: *mut bpf_spin_lock,
    remove_from_list: bool,
) -> i64 {
    bpf_spin_lock(lock_);

    let l = bpf_list_pop_front(head_);
    if l.is_null() {
        bpf_spin_unlock(lock_);
        return -1;
    }

    let n = entry_l(l);
    let res = (*n).list_data;

    if !remove_from_list {
        if bpf_list_push_back(head_, addr_of_mut!((*n).l)) != 0 {
            bpf_spin_unlock(lock_);
            return -2;
        }
    }

    bpf_spin_unlock(lock_);

    if remove_from_list {
        bpf_obj_drop(n.cast());
    }
    res
}

unsafe fn __read_from_unstash(idx: i32) -> i64 {
    let mapval = bpf_map_lookup_elem(&stashed_nodes, &idx) as *mut map_value;
    if mapval.is_null() {
        return -1;
    }

    let n = bpf_kptr_xchg(addr_of_mut!((*mapval).node).cast(), null_mut()) as *mut node_data;
    if n.is_null() {
        return -2;
    }

    let val = (*n).key;
    bpf_obj_drop(n.cast());
    val
}

// INSERT_READ_BOTH(rem_tree, rem_list, desc):
// insert_and_remove_tree_<rem_tree>_list_<rem_list>
macro_rules! insert_read_both {
    ($name:ident, $rem_tree:expr, $rem_list:expr) => {
        #[link_section = "tc"]
        #[no_mangle]
        extern "C" fn $name(_ctx: *const c_void) -> i64 {
            unsafe {
                let err = __insert_in_tree_and_list(
                    addr_of_mut!(head),
                    addr_of_mut!(root),
                    addr_of_mut!(lock),
                );
                if err != 0 {
                    return err;
                }

                let err = __read_from_tree(addr_of_mut!(root), addr_of_mut!(lock), $rem_tree);
                if err < 0 {
                    return err;
                }
                let tree_data = err;

                let err = __read_from_list(addr_of_mut!(head), addr_of_mut!(lock), $rem_list);
                if err < 0 {
                    return err;
                }
                let list_data = err;

                tree_data + list_data
            }
        }
    };
}

/* After successful insert of struct node_data into both collections:
 *   - it should have refcount = 2
 *   - removing / not removing the node_data from a collection after
 *     reading should have no effect on ability to read / remove from
 *     the other collection
 */
insert_read_both!(insert_and_remove_tree_true_list_true, true, true);
insert_read_both!(insert_and_remove_tree_false_list_false, false, false);
insert_read_both!(insert_and_remove_tree_true_list_false, true, false);
insert_read_both!(insert_and_remove_tree_false_list_true, false, true);

// The second INSERT_READ_BOTH: insert_and_remove_lf_tree_<rem_tree>_list_<rem_list>
macro_rules! insert_read_both_list_first {
    ($name:ident, $rem_tree:expr, $rem_list:expr) => {
        #[link_section = "tc"]
        #[no_mangle]
        extern "C" fn $name(_ctx: *const c_void) -> i64 {
            unsafe {
                let err = __insert_in_tree_and_list(
                    addr_of_mut!(head),
                    addr_of_mut!(root),
                    addr_of_mut!(lock),
                );
                if err != 0 {
                    return err;
                }

                let err = __read_from_list(addr_of_mut!(head), addr_of_mut!(lock), $rem_list);
                if err < 0 {
                    return err;
                }
                let list_data = err;

                let err = __read_from_tree(addr_of_mut!(root), addr_of_mut!(lock), $rem_tree);
                if err < 0 {
                    return err;
                }
                let tree_data = err;

                tree_data + list_data
            }
        }
    };
}

/* Similar to insert_read_both, but list data is read and possibly removed
 * first
 *
 * Results should be no different than reading and possibly removing rbtree
 * node first
 */
insert_read_both_list_first!(insert_and_remove_lf_tree_true_list_true, true, true);
insert_read_both_list_first!(insert_and_remove_lf_tree_false_list_false, false, false);
insert_read_both_list_first!(insert_and_remove_lf_tree_true_list_false, true, false);
insert_read_both_list_first!(insert_and_remove_lf_tree_false_list_true, false, true);

// INSERT_DOUBLE_READ_AND_DEL(read_fn, read_root, desc):
// insert_double_<read_fn>_and_del_<read_root>
macro_rules! insert_double_read_and_del {
    ($name:ident, $read_fn:ident, $read_root:ident) => {
        #[link_section = "tc"]
        #[no_mangle]
        extern "C" fn $name(_ctx: *const c_void) -> i64 {
            unsafe {
                let err = __insert_in_tree_and_list(
                    addr_of_mut!(head),
                    addr_of_mut!(root),
                    addr_of_mut!(lock),
                );
                if err != 0 {
                    return err;
                }

                let err = $read_fn(addr_of_mut!($read_root), addr_of_mut!(lock), true);
                if err < 0 {
                    return err;
                }
                let list_data = err;

                let err = $read_fn(addr_of_mut!($read_root), addr_of_mut!(lock), true);
                if err < 0 {
                    return err;
                }

                err + list_data
            }
        }
    };
}

/* Insert into both tree and list, then try reading-and-removing from either twice
 *
 * The second read-and-remove should fail on read step since the node has
 * already been removed
 */
insert_double_read_and_del!(insert_double___read_from_tree_and_del_root, __read_from_tree, root);
insert_double_read_and_del!(insert_double___read_from_list_and_del_head, __read_from_list, head);

// INSERT_STASH_READ(rem_tree, desc): insert_rbtree_and_stash__del_tree_<rem_tree>
macro_rules! insert_stash_read {
    ($name:ident, $rem_tree:expr) => {
        #[link_section = "tc"]
        #[no_mangle]
        extern "C" fn $name(_ctx: *const c_void) -> i64 {
            unsafe {
                let err = __stash_map_insert_tree(0, 42, addr_of_mut!(root), addr_of_mut!(lock));
                if err != 0 {
                    return err;
                }

                let err = __read_from_tree(addr_of_mut!(root), addr_of_mut!(lock), $rem_tree);
                if err < 0 {
                    return err;
                }
                let tree_data = err;

                let err = __read_from_unstash(0);
                if err < 0 {
                    return err;
                }
                let map_data = err;

                tree_data + map_data
            }
        }
    };
}

/* Stash a refcounted node in map_val, insert same node into tree, then try
 * reading data from tree then unstashed map_val, possibly removing from tree
 *
 * Removing from tree should have no effect on map_val kptr validity
 */
insert_stash_read!(insert_rbtree_and_stash__del_tree_true, true);
insert_stash_read!(insert_rbtree_and_stash__del_tree_false, false);

#[link_section = "tc"]
#[no_mangle]
extern "C" fn list_empty_test(_ctx: *const c_void) -> i32 {
    unsafe {
        bpf_spin_lock(addr_of_mut!(lock));
        if !bpf_list_empty(addr_of_mut!(head)) {
            bpf_spin_unlock(addr_of_mut!(lock));
            return -1;
        }
        bpf_spin_unlock(addr_of_mut!(lock));

        let node_new = bpf_obj_new(node_data_id()) as *mut node_data;
        if node_new.is_null() {
            return -2;
        }

        bpf_spin_lock(addr_of_mut!(lock));
        bpf_list_push_front(addr_of_mut!(head), addr_of_mut!((*node_new).l));

        if bpf_list_empty(addr_of_mut!(head)) {
            bpf_spin_unlock(addr_of_mut!(lock));
            return -3;
        }
        bpf_spin_unlock(addr_of_mut!(lock));
        0
    }
}

unsafe fn __add_in_list(head_: *mut bpf_list_head, lock_: *mut bpf_spin_lock) -> *mut node_data {
    let node_new = bpf_obj_new(node_data_id()) as *mut node_data;
    if node_new.is_null() {
        return null_mut();
    }

    let node_ref = bpf_refcount_acquire(node_new.cast()) as *mut node_data;

    bpf_spin_lock(lock_);
    bpf_list_push_front(head_, addr_of_mut!((*node_new).l));
    bpf_spin_unlock(lock_);
    node_ref
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn list_is_edge_test1(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut err: i32 = 0;

        let node_last = __add_in_list(addr_of_mut!(head), addr_of_mut!(lock));
        if node_last.is_null() {
            return -1;
        }

        let node_first = __add_in_list(addr_of_mut!(head), addr_of_mut!(lock));
        if node_first.is_null() {
            bpf_obj_drop(node_last.cast());
            return -2;
        }

        bpf_spin_lock(addr_of_mut!(lock));
        'fail: {
            if !bpf_list_is_first(addr_of_mut!(head), addr_of_mut!((*node_first).l)) {
                err = -3;
                break 'fail;
            }
            if !bpf_list_is_last(addr_of_mut!(head), addr_of_mut!((*node_last).l)) {
                err = -4;
            }
        }

        bpf_spin_unlock(addr_of_mut!(lock));
        bpf_obj_drop(node_first.cast());
        bpf_obj_drop(node_last.cast());
        err
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn list_is_edge_test2(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut err: i64 = 0;

        let a = __add_in_list(addr_of_mut!(head), addr_of_mut!(lock));
        if a.is_null() {
            return -1;
        }

        let b = __add_in_list(addr_of_mut!(head), addr_of_mut!(lock));
        if b.is_null() {
            bpf_obj_drop(a.cast());
            return -2;
        }

        bpf_spin_lock(addr_of_mut!(lock));
        'out_unlock: {
            let front = bpf_list_front(addr_of_mut!(head));
            let back = bpf_list_back(addr_of_mut!(head));
            if front.is_null() || back.is_null() {
                err = -3;
                break 'out_unlock;
            }

            if !bpf_list_is_first(addr_of_mut!(head), front)
                || bpf_list_is_last(addr_of_mut!(head), front)
            {
                err = -4;
                break 'out_unlock;
            }

            if !bpf_list_is_last(addr_of_mut!(head), back)
                || bpf_list_is_first(addr_of_mut!(head), back)
            {
                err = -5;
                break 'out_unlock;
            }
        }

        bpf_spin_unlock(addr_of_mut!(lock));
        bpf_obj_drop(a.cast());
        bpf_obj_drop(b.cast());
        err as i32
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn list_is_edge_test3(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut err: i64 = 0;

        let tmp = __add_in_list(addr_of_mut!(head), addr_of_mut!(lock));
        if tmp.is_null() {
            return -1;
        }

        bpf_spin_lock(addr_of_mut!(lock));
        let node = bpf_list_front(addr_of_mut!(head));
        if node.is_null() {
            bpf_spin_unlock(addr_of_mut!(lock));
            bpf_obj_drop(tmp.cast());
            return -2;
        }

        if !bpf_list_is_first(addr_of_mut!(head), node)
            || !bpf_list_is_last(addr_of_mut!(head), node)
        {
            err = -3;
        }
        bpf_spin_unlock(addr_of_mut!(lock));

        bpf_obj_drop(tmp.cast());
        err as i32
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn list_del_test1(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut err: i32 = 0;

        let node_last = __add_in_list(addr_of_mut!(head), addr_of_mut!(lock));
        if node_last.is_null() {
            return -1;
        }

        let node_first = __add_in_list(addr_of_mut!(head), addr_of_mut!(lock));
        if node_first.is_null() {
            bpf_obj_drop(node_last.cast());
            return -2;
        }

        bpf_spin_lock(addr_of_mut!(lock));
        let bpf_node_last = bpf_list_del(addr_of_mut!(head), addr_of_mut!((*node_last).l));
        let bpf_node_first = bpf_list_del(addr_of_mut!(head), addr_of_mut!((*node_first).l));
        bpf_spin_unlock(addr_of_mut!(lock));

        if !bpf_node_first.is_null() {
            bpf_obj_drop(entry_l(bpf_node_first).cast());
        } else {
            err = -3;
        }

        if !bpf_node_last.is_null() {
            bpf_obj_drop(entry_l(bpf_node_last).cast());
        } else {
            err = -4;
        }

        bpf_obj_drop(node_first.cast());
        bpf_obj_drop(node_last.cast());
        err
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn list_del_test2(_ctx: *const c_void) -> i32 {
    unsafe {
        let err = __insert_in_tree_and_list(
            addr_of_mut!(head),
            addr_of_mut!(root),
            addr_of_mut!(lock),
        );
        if err != 0 {
            return err as i32;
        }

        bpf_spin_lock(addr_of_mut!(lock));
        let rb = bpf_rbtree_first(addr_of_mut!(root));
        if rb.is_null() {
            bpf_spin_unlock(addr_of_mut!(lock));
            return -4;
        }

        let rb = bpf_rbtree_remove(addr_of_mut!(root), rb);
        if rb.is_null() {
            bpf_spin_unlock(addr_of_mut!(lock));
            return -5;
        }

        let n = entry_r(rb);
        let l = bpf_list_del(addr_of_mut!(head), addr_of_mut!((*n).l));
        bpf_spin_unlock(addr_of_mut!(lock));
        bpf_obj_drop(n.cast());
        if l.is_null() {
            return -6;
        }

        bpf_obj_drop(entry_l(l).cast());
        0
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn list_del_test3(_ctx: *const c_void) -> i32 {
    unsafe {
        let err: i64;

        let tmp = __add_in_list(addr_of_mut!(head), addr_of_mut!(lock));
        if tmp.is_null() {
            return -1;
        }

        'fail: {
            bpf_spin_lock(addr_of_mut!(lock));
            let bpf_node = bpf_list_front(addr_of_mut!(head));
            if bpf_node.is_null() {
                bpf_spin_unlock(addr_of_mut!(lock));
                err = -2;
                break 'fail;
            }

            let l = bpf_list_del(addr_of_mut!(head), bpf_node);
            bpf_spin_unlock(addr_of_mut!(lock));
            if l.is_null() {
                err = -3;
                break 'fail;
            }

            bpf_obj_drop(entry_l(l).cast());
            bpf_obj_drop(tmp.cast());
            return 0;
        }

        bpf_obj_drop(tmp.cast());
        err as i32
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn list_add_test1(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut err: i64;

        let node_first = __add_in_list(addr_of_mut!(head), addr_of_mut!(lock));
        if node_first.is_null() {
            return -1;
        }

        'fail: {
            let new_node = bpf_obj_new(node_data_id()) as *mut node_data;
            if new_node.is_null() {
                err = -2;
                break 'fail;
            }

            bpf_spin_lock(addr_of_mut!(lock));
            err = bpf_list_add(
                addr_of_mut!(head),
                addr_of_mut!((*new_node).l),
                addr_of_mut!((*node_first).l),
            ) as i64;
            bpf_spin_unlock(addr_of_mut!(lock));
            if err != 0 {
                err = -3;
                break 'fail;
            }
        }

        bpf_obj_drop(node_first.cast());
        err as i32
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn list_add_test2(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut err: i64;

        let tmp = __add_in_list(addr_of_mut!(head), addr_of_mut!(lock));
        if tmp.is_null() {
            return -1;
        }

        'fail: {
            let new_node = bpf_obj_new(node_data_id()) as *mut node_data;
            if new_node.is_null() {
                err = -2;
                break 'fail;
            }

            bpf_spin_lock(addr_of_mut!(lock));
            let bpf_node = bpf_list_front(addr_of_mut!(head));
            if bpf_node.is_null() {
                bpf_spin_unlock(addr_of_mut!(lock));
                bpf_obj_drop(new_node.cast());
                err = -3;
                break 'fail;
            }

            err = bpf_list_add(addr_of_mut!(head), addr_of_mut!((*new_node).l), bpf_node) as i64;
            bpf_spin_unlock(addr_of_mut!(lock));
            if err != 0 {
                err = -4;
                break 'fail;
            }
        }

        bpf_obj_drop(tmp.cast());
        err as i32
    }
}

#[allow(non_camel_case_types)]
#[btf_tag]
#[repr(C)]
struct uninit_head_val {
    lock: bpf_spin_lock,
    #[btf_tag(decl_tag = "contains:node_data:l")]
    head: bpf_list_head,
}

#[link_section = ".maps"]
#[no_mangle]
static uninit_head_map: BpfMap<i32, uninit_head_val, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "tc"]
#[no_mangle]
extern "C" fn list_push_back_uninit_head(_ctx: *const c_void) -> i32 {
    unsafe {
        let key: i32 = 0;

        let st = bpf_map_lookup_elem(&uninit_head_map, &key) as *mut uninit_head_val;
        if st.is_null() {
            return -1;
        }

        let node = bpf_obj_new(node_data_id()) as *mut node_data;
        if node.is_null() {
            return -1;
        }

        bpf_spin_lock(addr_of_mut!((*st).lock));
        let ret = bpf_list_push_back(addr_of_mut!((*st).head), addr_of_mut!((*node).l));
        bpf_spin_unlock(addr_of_mut!((*st).lock));

        ret
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn list_del_without_lock_fail(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return -1;
        }

        /* Error case: delete list node without holding lock */
        let l = bpf_list_del(addr_of_mut!(head), addr_of_mut!((*n).l));
        bpf_obj_drop(n.cast());
        if l.is_null() {
            return -2;
        }
        bpf_obj_drop(entry_l(l).cast());

        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn list_add_without_lock_fail(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return -1;
        }

        let prev = bpf_obj_new(node_data_id()) as *mut node_data;
        if prev.is_null() {
            bpf_obj_drop(n.cast());
            return -1;
        }

        /* Error case: add list node without holding lock */
        let err = bpf_list_add(addr_of_mut!(head), addr_of_mut!((*n).l), addr_of_mut!((*prev).l));
        bpf_obj_drop(prev.cast());
        if err != 0 {
            return -2;
        }

        0
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_refcounted_node_ref_escapes(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_acquire_id()) as *mut node_acquire;
        if n.is_null() {
            return 1;
        }

        bpf_spin_lock(addr_of_mut!(alock));
        bpf_rbtree_add(addr_of_mut!(aroot), addr_of_mut!((*n).node), less_a);
        let m = bpf_refcount_acquire(n.cast()) as *mut node_acquire;
        bpf_spin_unlock(addr_of_mut!(alock));
        if m.is_null() {
            return 2;
        }

        (*m).key = 2;
        bpf_obj_drop(m.cast());
        0
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_refcounted_node_ref_escapes_owning_input(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_acquire_id()) as *mut node_acquire;
        if n.is_null() {
            return 1;
        }

        let m = bpf_refcount_acquire(n.cast()) as *mut node_acquire;
        (*m).key = 2;

        bpf_spin_lock(addr_of_mut!(alock));
        bpf_rbtree_add(addr_of_mut!(aroot), addr_of_mut!((*n).node), less_a);
        bpf_spin_unlock(addr_of_mut!(alock));

        bpf_obj_drop(m.cast());

        0
    }
}

unsafe fn __stash_map_empty_xchg(n: *mut node_data, idx: i32) -> i64 {
    let mapval = bpf_map_lookup_elem(&stashed_nodes, &idx) as *mut map_value;

    if mapval.is_null() {
        bpf_obj_drop(n.cast());
        return 1;
    }
    let n = bpf_kptr_xchg(addr_of_mut!((*mapval).node).cast(), n.cast()) as *mut node_data;
    if !n.is_null() {
        bpf_obj_drop(n.cast());
        return 2;
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_wrong_owner_remove_fail_a1(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return 1;
        }
        let m = bpf_refcount_acquire(n.cast()) as *mut node_data;

        if __stash_map_empty_xchg(n, 0) != 0 {
            bpf_obj_drop(m.cast());
            return 2;
        }

        if __stash_map_empty_xchg(m, 1) != 0 {
            return 3;
        }

        0
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_wrong_owner_remove_fail_b(_ctx: *const c_void) -> i64 {
    unsafe {
        let idx: i32 = 0;

        let mapval = bpf_map_lookup_elem(&stashed_nodes, &idx) as *mut map_value;
        if mapval.is_null() {
            return 1;
        }

        let n = bpf_kptr_xchg(addr_of_mut!((*mapval).node).cast(), null_mut()) as *mut node_data;
        if n.is_null() {
            return 2;
        }

        bpf_spin_lock(addr_of_mut!(block));

        bpf_rbtree_add(addr_of_mut!(broot), addr_of_mut!((*n).r), less);

        bpf_spin_unlock(addr_of_mut!(block));
        0
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_wrong_owner_remove_fail_a2(_ctx: *const c_void) -> i64 {
    unsafe {
        let idx: i32 = 1;

        let mapval = bpf_map_lookup_elem(&stashed_nodes, &idx) as *mut map_value;
        if mapval.is_null() {
            return 1;
        }

        let m = bpf_kptr_xchg(addr_of_mut!((*mapval).node).cast(), null_mut()) as *mut node_data;
        if m.is_null() {
            return 2;
        }
        bpf_spin_lock(addr_of_mut!(lock));

        /* make m non-owning ref */
        bpf_list_push_back(addr_of_mut!(head), addr_of_mut!((*m).l));
        let res = bpf_rbtree_remove(addr_of_mut!(root), addr_of_mut!((*m).r));

        bpf_spin_unlock(addr_of_mut!(lock));
        if !res.is_null() {
            bpf_obj_drop(entry_r(res).cast());
            return 3;
        }
        0
    }
}

// BPF_PROG(rbtree_sleepable_rcu, struct file *file, ...): the arguments are
// unused, so the program takes the raw context.
#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rbtree_sleepable_rcu(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut m: *mut node_data = null_mut();

        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return 0;
        }

        bpf_rcu_read_lock();
        bpf_spin_lock(addr_of_mut!(lock));
        bpf_rbtree_add(addr_of_mut!(root), addr_of_mut!((*n).r), less);
        'err_out: {
            let rb = bpf_rbtree_first(addr_of_mut!(root));
            if rb.is_null() {
                break 'err_out;
            }

            let rb = bpf_rbtree_remove(addr_of_mut!(root), rb);
            if rb.is_null() {
                break 'err_out;
            }

            m = entry_r(rb);
        }

        bpf_spin_unlock(addr_of_mut!(lock));
        bpf_rcu_read_unlock();
        if !m.is_null() {
            bpf_obj_drop(m.cast());
        }
        0
    }
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rbtree_sleepable_rcu_no_explicit_rcu_lock(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut m: *mut node_data = null_mut();

        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return 0;
        }

        /* No explicit bpf_rcu_read_lock */
        bpf_spin_lock(addr_of_mut!(lock));
        bpf_rbtree_add(addr_of_mut!(root), addr_of_mut!((*n).r), less);
        'err_out: {
            let rb = bpf_rbtree_first(addr_of_mut!(root));
            if rb.is_null() {
                break 'err_out;
            }

            let rb = bpf_rbtree_remove(addr_of_mut!(root), rb);
            if rb.is_null() {
                break 'err_out;
            }

            m = entry_r(rb);
        }

        bpf_spin_unlock(addr_of_mut!(lock));
        /* No explicit bpf_rcu_read_unlock */
        if !m.is_null() {
            bpf_obj_drop(m.cast());
        }
        0
    }
}

// private(kptr_ref) u64 ref;
#[allow(non_upper_case_globals)]
#[link_section = ".bss.kptr_ref"]
static mut r#ref: u64 = 0;

unsafe fn probe_read_refcount() -> i32 {
    let mut refcount: u32 = 0;

    bpf_probe_read_kernel(
        &mut refcount,
        core::mem::size_of::<u32>() as u32,
        r#ref as usize as *const c_void,
    );
    refcount as i32
}

unsafe fn __insert_in_list(
    head_: *mut bpf_list_head,
    lock_: *mut bpf_spin_lock,
    node: *mut *mut node_data,
) -> i32 {
    let node_new = bpf_obj_new(node_data_id()) as *mut node_data;
    if node_new.is_null() {
        return -1;
    }

    let node_ref = bpf_refcount_acquire(node_new.cast()) as *mut node_data;
    let node_old = bpf_kptr_xchg(node.cast(), node_new.cast()) as *mut node_data;
    if !node_old.is_null() {
        bpf_obj_drop(node_old.cast());
        bpf_obj_drop(node_ref.cast());
        return -2;
    }

    bpf_spin_lock(lock_);
    bpf_list_push_front(head_, addr_of_mut!((*node_ref).l));
    r#ref = addr_of_mut!((*node_ref).r#ref) as usize as u64;
    bpf_spin_unlock(lock_);
    probe_read_refcount()
}

#[link_section = ".maps"]
#[no_mangle]
static percpu_hash: BpfMap<i32, map_value, { maps::PERCPU_HASH }, 1> = BpfMap::new();

#[link_section = "tc"]
#[no_mangle]
extern "C" fn percpu_hash_refcount_leak(_ctx: *const c_void) -> i32 {
    unsafe {
        let key: i32 = 0;

        let v = bpf_map_lookup_percpu_elem(&percpu_hash, &key, 0) as *mut map_value;
        if v.is_null() {
            return 0;
        }

        __insert_in_list(addr_of_mut!(head), addr_of_mut!(lock), addr_of_mut!((*v).node))
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn clear_percpu_hash_kptr(_ctx: *const c_void) -> i32 {
    unsafe {
        let key: i32 = 0;

        let v = bpf_map_lookup_percpu_elem(&percpu_hash, &key, 0) as *mut map_value;
        if v.is_null() {
            return 0;
        }

        let n = bpf_kptr_xchg(addr_of_mut!((*v).node).cast(), null_mut()) as *mut node_data;
        if n.is_null() {
            return 0;
        }
        bpf_obj_drop(n.cast());
        probe_read_refcount()
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn check_percpu_hash_refcount(_ctx: *const c_void) -> i32 {
    unsafe { probe_read_refcount() }
}

btf_type_tags! {
    map_value.node: kptr;
}

test_tags! {
    insert_and_remove_tree_true_list_true: __description("insert_read_both: remove from tree + list"), __success, __retval(579);
    insert_and_remove_tree_false_list_false: __description("insert_read_both: remove from neither"), __success, __retval(579);
    insert_and_remove_tree_true_list_false: __description("insert_read_both: remove from tree"), __success, __retval(579);
    insert_and_remove_tree_false_list_true: __description("insert_read_both: remove from list"), __success, __retval(579);
    insert_and_remove_lf_tree_true_list_true: __description("insert_read_both_list_first: remove from tree + list"), __success, __retval(579);
    insert_and_remove_lf_tree_false_list_false: __description("insert_read_both_list_first: remove from neither"), __success, __retval(579);
    insert_and_remove_lf_tree_true_list_false: __description("insert_read_both_list_first: remove from tree"), __success, __retval(579);
    insert_and_remove_lf_tree_false_list_true: __description("insert_read_both_list_first: remove from list"), __success, __retval(579);
    insert_double___read_from_tree_and_del_root: __description("insert_double_del: 2x read-and-del from tree"), __success, __retval(-1);
    insert_double___read_from_list_and_del_head: __description("insert_double_del: 2x read-and-del from list"), __success, __retval(-1);
    insert_rbtree_and_stash__del_tree_true: __description("insert_stash_read: remove from tree"), __success, __retval(84);
    insert_rbtree_and_stash__del_tree_false: __description("insert_stash_read: don't remove from tree"), __success, __retval(84);
    list_empty_test: __description("list_empty_test: list empty before add, non-empty after add"), __success, __retval(0);
    list_is_edge_test1: __description("list_is_edge_test1: is_first on first node, is_last on last node"), __success, __retval(0);
    list_is_edge_test2: __description("list_is_edge_test2: accept list_front/list_back return value"), __success, __retval(0);
    list_is_edge_test3: __description("list_is_edge_test3: single node is both first and last"), __success, __retval(0);
    list_del_test1: __description("list_del_test1: del returns removed nodes"), __success, __retval(0);
    list_del_test2: __description("list_del_test2: remove an arbitrary node from the list"), __success, __retval(0);
    list_del_test3: __description("list_del_test3: list_del accepts list_front return value as node"), __success, __retval(0);
    list_add_test1: __description("list_add_test1: insert new node after prev"), __success, __retval(0);
    list_add_test2: __description("list_add_test2: list_add accepts list_front return value as prev"), __success, __retval(0);
    list_push_back_uninit_head: __description("list_push_back_uninit_head: push_back on 0-initialized list head"), __success, __retval(0);
    list_del_without_lock_fail: __failure, __msg("bpf_spin_lock at off=32 must be held for bpf_list_head");
    list_add_without_lock_fail: __failure, __msg("bpf_spin_lock at off=32 must be held for bpf_list_head");
    rbtree_refcounted_node_ref_escapes: __success;
    rbtree_refcounted_node_ref_escapes_owning_input: __success;
    rbtree_sleepable_rcu: __success;
    rbtree_sleepable_rcu_no_explicit_rcu_lock: __success;
}

bpf_object!("GPL");
