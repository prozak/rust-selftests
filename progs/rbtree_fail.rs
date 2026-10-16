// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/rbtree_fail.c
// (bpf-rs-core idiom).
//
// Verifier rejection tests (prog_tests/rbtree.c: RUN_TESTS(rbtree_fail));
// test_tags! mirrors the C __failure/__msg tags, and
// rbtree_api_remove_unadded_node is the one program that loads and runs.
// glock, groot and groot2 are C `__hidden` statics in SEC(".data.A"), laid
// out as in the C object (scripts/private_sections.py), which is the order
// the code first refers to them, not C's declaration order: groot 0,
// glock 16, groot2 24 (`llvm-readelf -s rbtree_fail.bpf.o`), hence
// "bpf_spin_lock at off=16"; they are declared in that order here too. The
// three bad less() callbacks call kfuncs the verifier rejects
// inside an rbtree callback; add_with_cb() is C's __always_inline helper
// taking the callback as a parameter.

// BTF_TYPE_ID: node_data_id local struct node_data

use bpf_rs_core::helpers::{bpf_spin_lock, bpf_spin_unlock, sink};
use bpf_rs_core::{bpf_object, test_tags};
use btf_macros::btf_tag;
use core::ffi::c_void;
use core::ptr::addr_of_mut;

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
#[repr(C)]
struct node_data {
    key: i64,
    data: i64,
    node: bpf_rb_node,
}

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:node")]
#[link_section = ".data.A"]
static mut groot: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut glock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:node")]
#[link_section = ".data.A"]
static mut groot2: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

type LessFn = extern "C" fn(*mut bpf_rb_node, *const bpf_rb_node) -> bool;

extern "C" {
    fn node_data_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_rbtree_add(root: *mut bpf_rb_root, node: *mut bpf_rb_node, less: LessFn) -> i32;
    fn bpf_rbtree_first(root: *mut bpf_rb_root) -> *mut bpf_rb_node;
    fn bpf_rbtree_remove(root: *mut bpf_rb_root, node: *mut bpf_rb_node) -> *mut bpf_rb_node;
}

// container_of(ptr, struct node_data, node)
#[inline(always)]
unsafe fn entry(n: *mut bpf_rb_node) -> *mut node_data {
    (n as *mut u8).sub(core::mem::offset_of!(node_data, node)) as *mut node_data
}

extern "C" fn less(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let node_a = entry(a);
        let node_b = entry(b as *mut bpf_rb_node);

        (*node_a).key < (*node_b).key
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_nolock_add(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return 1;
        }

        bpf_rbtree_add(addr_of_mut!(groot), addr_of_mut!((*n).node), less);
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_nolock_remove(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return 1;
        }

        bpf_spin_lock(addr_of_mut!(glock));
        bpf_rbtree_add(addr_of_mut!(groot), addr_of_mut!((*n).node), less);
        bpf_spin_unlock(addr_of_mut!(glock));

        bpf_rbtree_remove(addr_of_mut!(groot), addr_of_mut!((*n).node));
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_nolock_first(_ctx: *const c_void) -> i64 {
    unsafe {
        bpf_rbtree_first(addr_of_mut!(groot));
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_remove_unadded_node(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return 1;
        }

        let m = bpf_obj_new(node_data_id()) as *mut node_data;
        if m.is_null() {
            bpf_obj_drop(n.cast());
            return 1;
        }

        bpf_spin_lock(addr_of_mut!(glock));
        bpf_rbtree_add(addr_of_mut!(groot), addr_of_mut!((*n).node), less);

        let res_n = bpf_rbtree_remove(addr_of_mut!(groot), addr_of_mut!((*n).node));

        let res_m = bpf_rbtree_remove(addr_of_mut!(groot), addr_of_mut!((*m).node));
        bpf_spin_unlock(addr_of_mut!(glock));

        bpf_obj_drop(m.cast());
        if !res_n.is_null() {
            bpf_obj_drop(entry(res_n).cast());
        }
        if !res_m.is_null() {
            bpf_obj_drop(entry(res_m).cast());
            /* m was not added to the rbtree */
            return 2;
        }

        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_remove_no_drop(_ctx: *const c_void) -> i64 {
    unsafe {
        'unlock_err: {
            bpf_spin_lock(addr_of_mut!(glock));
            let res = bpf_rbtree_first(addr_of_mut!(groot));
            if res.is_null() {
                break 'unlock_err;
            }

            let res = bpf_rbtree_remove(addr_of_mut!(groot), res);

            if !res.is_null() {
                let mut n = entry(res);
                sink(&mut n);
            }
            bpf_spin_unlock(addr_of_mut!(glock));

            /* if (res) { bpf_obj_drop(n); } is missing here */
            return 0;
        }

        bpf_spin_unlock(addr_of_mut!(glock));
        1
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_add_to_multiple_trees(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return 1;
        }

        bpf_spin_lock(addr_of_mut!(glock));
        bpf_rbtree_add(addr_of_mut!(groot), addr_of_mut!((*n).node), less);

        /* This add should fail since n already in groot's tree */
        bpf_rbtree_add(addr_of_mut!(groot2), addr_of_mut!((*n).node), less);
        bpf_spin_unlock(addr_of_mut!(glock));
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_use_unchecked_remove_retval(_ctx: *const c_void) -> i64 {
    unsafe {
        'err_out: {
            bpf_spin_lock(addr_of_mut!(glock));

            let res = bpf_rbtree_first(addr_of_mut!(groot));
            if res.is_null() {
                break 'err_out;
            }
            let res = bpf_rbtree_remove(addr_of_mut!(groot), res);

            bpf_spin_unlock(addr_of_mut!(glock));

            bpf_spin_lock(addr_of_mut!(glock));
            /* Must check res for NULL before using in rbtree_add below */
            bpf_rbtree_add(addr_of_mut!(groot), res, less);
            bpf_spin_unlock(addr_of_mut!(glock));
            return 0;
        }

        bpf_spin_unlock(addr_of_mut!(glock));
        1
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_add_release_unlock_escape(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return 1;
        }

        bpf_spin_lock(addr_of_mut!(glock));
        bpf_rbtree_add(addr_of_mut!(groot), addr_of_mut!((*n).node), less);
        bpf_spin_unlock(addr_of_mut!(glock));

        bpf_spin_lock(addr_of_mut!(glock));
        /* After add() in previous critical section, n should be
         * release_on_unlock and released after previous spin_unlock,
         * so should not be possible to use it here
         */
        bpf_rbtree_remove(addr_of_mut!(groot), addr_of_mut!((*n).node));
        bpf_spin_unlock(addr_of_mut!(glock));
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_first_release_unlock_escape(_ctx: *const c_void) -> i64 {
    unsafe {
        bpf_spin_lock(addr_of_mut!(glock));
        let res = bpf_rbtree_first(addr_of_mut!(groot));
        if res.is_null() {
            bpf_spin_unlock(addr_of_mut!(glock));
            return 1;
        }
        let n = entry(res);
        bpf_spin_unlock(addr_of_mut!(glock));

        bpf_spin_lock(addr_of_mut!(glock));
        /* After first() in previous critical section, n should be
         * release_on_unlock and released after previous spin_unlock,
         * so should not be possible to use it here
         */
        bpf_rbtree_remove(addr_of_mut!(groot), addr_of_mut!((*n).node));
        bpf_spin_unlock(addr_of_mut!(glock));
        0
    }
}

extern "C" fn less__bad_fn_call_add(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let node_a = entry(a);
        let node_b = entry(b as *mut bpf_rb_node);
        bpf_rbtree_add(addr_of_mut!(groot), addr_of_mut!((*node_a).node), less);

        (*node_a).key < (*node_b).key
    }
}

extern "C" fn less__bad_fn_call_remove(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let node_a = entry(a);
        let node_b = entry(b as *mut bpf_rb_node);
        bpf_rbtree_remove(addr_of_mut!(groot), addr_of_mut!((*node_a).node));

        (*node_a).key < (*node_b).key
    }
}

extern "C" fn less__bad_fn_call_first_unlock_after(
    a: *mut bpf_rb_node,
    b: *const bpf_rb_node,
) -> bool {
    unsafe {
        let node_a = entry(a);
        let node_b = entry(b as *mut bpf_rb_node);
        bpf_rbtree_first(addr_of_mut!(groot));
        bpf_spin_unlock(addr_of_mut!(glock));

        (*node_a).key < (*node_b).key
    }
}

#[inline(always)]
unsafe fn add_with_cb(cb: LessFn) -> i64 {
    let n = bpf_obj_new(node_data_id()) as *mut node_data;
    if n.is_null() {
        return 1;
    }

    bpf_spin_lock(addr_of_mut!(glock));
    bpf_rbtree_add(addr_of_mut!(groot), addr_of_mut!((*n).node), cb);
    bpf_spin_unlock(addr_of_mut!(glock));
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_add_bad_cb_bad_fn_call_add(_ctx: *const c_void) -> i64 {
    unsafe { add_with_cb(less__bad_fn_call_add) }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_add_bad_cb_bad_fn_call_remove(_ctx: *const c_void) -> i64 {
    unsafe { add_with_cb(less__bad_fn_call_remove) }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_api_add_bad_cb_bad_fn_call_first_unlock_after(_ctx: *const c_void) -> i64 {
    unsafe { add_with_cb(less__bad_fn_call_first_unlock_after) }
}

test_tags! {
    rbtree_api_nolock_add: __failure, __msg("bpf_spin_lock at off=16 must be held for bpf_rb_root");
    rbtree_api_nolock_remove: __failure, __msg("bpf_spin_lock at off=16 must be held for bpf_rb_root");
    rbtree_api_nolock_first: __failure, __msg("bpf_spin_lock at off=16 must be held for bpf_rb_root");
    rbtree_api_remove_unadded_node: __retval(0);
    rbtree_api_remove_no_drop: __failure, __msg("Unreleased reference id=3 alloc_insn={{[0-9]+}}");
    rbtree_api_add_to_multiple_trees: __failure, __msg("R2 expected pointer to allocated object");
    rbtree_api_use_unchecked_remove_retval: __failure, __msg("Possibly NULL pointer passed to trusted R2");
    rbtree_api_add_release_unlock_escape: __failure, __msg("bpf_rbtree_remove can only take non-owning or refcounted bpf_rb_node pointer");
    rbtree_api_first_release_unlock_escape: __failure, __msg("bpf_rbtree_remove can only take non-owning or refcounted bpf_rb_node pointer");
    rbtree_api_add_bad_cb_bad_fn_call_add: __failure, __msg("R2 expected pointer to allocated object");
    rbtree_api_add_bad_cb_bad_fn_call_remove: __failure, __msg("rbtree_remove not allowed in rbtree cb");
    rbtree_api_add_bad_cb_bad_fn_call_first_unlock_after: __failure, __msg("can't spin_{lock,unlock} in rbtree cb");
}

bpf_object!("GPL");
