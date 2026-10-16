// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 KylinSoft Corporation. */
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/rbtree_search_kptr.c
// (bpf-rs-core idiom).
//
// root/lock and root_r/lock_r are C `private(A)`/`private(B)` statics:
// `__hidden` in SEC(".data.A"/".data.B"), so BTF_VAR_STATIC and the maps are
// not mmapped by libbpf. A private Rust static (no #[no_mangle]) gets the
// same linkage (see test_spin_lock.rs); rust-bpf's #[btf_tag] still finds
// it by its debug-info name and puts C's __contains(T, node) decl tag on
// it. The three local types are allocated with bpf_obj_new() through their
// own `// BTF_TYPE_ID:` externs like C's bpf_obj_new(typeof(*p)); the
// __kptr members are declared with btf_type_tags! at the bottom.
//
// The programs return __LINE__ to say which check failed; the constants
// below are the C file's line numbers, so the objects agree.

// BTF_TYPE_ID: node_data_id local struct node_data
// BTF_TYPE_ID: tree_node_id local struct tree_node
// BTF_TYPE_ID: tree_node_ref_id local struct tree_node_ref

use bpf_rs_core::helpers::{bpf_kptr_xchg, bpf_spin_lock, bpf_spin_unlock};
use bpf_rs_core::{bpf_object, btf_type_tags};
use btf_macros::btf_tag;
use core::ffi::c_void;
use core::ptr::addr_of_mut;

const NR_NODES: i32 = 16;

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
    data: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct tree_node {
    node: bpf_rb_node,
    key: u64,
    node_data: *mut node_data,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct tree_node_ref {
    r#ref: bpf_refcount,
    node: bpf_rb_node,
    key: u64,
    node_data: *mut node_data,
}

#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut lock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:tree_node:node")]
#[link_section = ".data.A"]
static mut root: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

#[allow(non_upper_case_globals)]
#[link_section = ".data.B"]
static mut lock_r: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:tree_node_ref:node")]
#[link_section = ".data.B"]
static mut root_r: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

extern "C" {
    fn node_data_id() -> u64;
    fn tree_node_id() -> u64;
    fn tree_node_ref_id() -> u64;
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
    fn bpf_rbtree_first(root: *mut bpf_rb_root) -> *mut bpf_rb_node;
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

// container_of(ptr, struct tree_node, node) / tree_node_ref
#[inline(always)]
unsafe fn tn_of(n: *mut bpf_rb_node) -> *mut tree_node {
    (n as *mut u8).sub(core::mem::offset_of!(tree_node, node)) as *mut tree_node
}

#[inline(always)]
unsafe fn tnr_of(n: *mut bpf_rb_node) -> *mut tree_node_ref {
    (n as *mut u8).sub(core::mem::offset_of!(tree_node_ref, node)) as *mut tree_node_ref
}

extern "C" fn less(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let node_a = tn_of(a);
        let node_b = tn_of(b as *mut bpf_rb_node);

        (*node_a).key < (*node_b).key
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn rbtree_search_kptr(_ctx: *const c_void) -> i64 {
    let lookup_key: i32 = NR_NODES / 2;
    let lookup_data: i32 = NR_NODES / 2;
    let ret: i32;

    unsafe {
        let mut i: i32 = 0;
        while i < NR_NODES && can_loop() {
            let tnode = bpf_obj_new(tree_node_id()) as *mut tree_node;
            if tnode.is_null() {
                return 60;
            }

            let node_data = bpf_obj_new(node_data_id()) as *mut node_data;
            if node_data.is_null() {
                bpf_obj_drop(tnode.cast());
                return 65;
            }

            (*tnode).key = i as u64;
            (*node_data).data = i;

            let node_data: *mut node_data =
                bpf_kptr_xchg(addr_of_mut!((*tnode).node_data).cast(), node_data.cast()).cast();
            if !node_data.is_null() {
                bpf_obj_drop(node_data.cast());
            }

            bpf_spin_lock(addr_of_mut!(lock));
            bpf_rbtree_add(addr_of_mut!(root), addr_of_mut!((*tnode).node), less);
            bpf_spin_unlock(addr_of_mut!(lock));
            i += 1;
        }

        'fail: {
            bpf_spin_lock(addr_of_mut!(lock));
            let mut rb_n = bpf_rbtree_root(addr_of_mut!(root));
            while !rb_n.is_null() && can_loop() {
                let tnode = tn_of(rb_n);
                let node_data: *mut node_data =
                    bpf_kptr_xchg(addr_of_mut!((*tnode).node_data).cast(), core::ptr::null_mut())
                        .cast();
                if node_data.is_null() {
                    ret = 86;
                    break 'fail;
                }

                let data = (*node_data).data;
                let node_data: *mut node_data =
                    bpf_kptr_xchg(addr_of_mut!((*tnode).node_data).cast(), node_data.cast()).cast();
                if !node_data.is_null() {
                    bpf_spin_unlock(addr_of_mut!(lock));
                    bpf_obj_drop(node_data.cast());
                    return 95;
                }

                if lookup_key as u64 == (*tnode).key {
                    if data == lookup_data {
                        break;
                    }

                    ret = 102;
                    break 'fail;
                }

                if (lookup_key as u64) < (*tnode).key {
                    rb_n = bpf_rbtree_left(addr_of_mut!(root), rb_n);
                } else {
                    rb_n = bpf_rbtree_right(addr_of_mut!(root), rb_n);
                }
            }
            bpf_spin_unlock(addr_of_mut!(lock));

            while can_loop() {
                bpf_spin_lock(addr_of_mut!(lock));
                let rb_n = bpf_rbtree_first(addr_of_mut!(root));
                if rb_n.is_null() {
                    bpf_spin_unlock(addr_of_mut!(lock));
                    return 0;
                }

                let rb_n = bpf_rbtree_remove(addr_of_mut!(root), rb_n);
                if rb_n.is_null() {
                    ret = 123;
                    break 'fail;
                }
                bpf_spin_unlock(addr_of_mut!(lock));

                let tnode = tn_of(rb_n);

                let node_data: *mut node_data =
                    bpf_kptr_xchg(addr_of_mut!((*tnode).node_data).cast(), core::ptr::null_mut())
                        .cast();
                if !node_data.is_null() {
                    bpf_obj_drop(node_data.cast());
                }

                bpf_obj_drop(tnode.cast());
            }

            return 0;
        }
        bpf_spin_unlock(addr_of_mut!(lock));
    }
    ret as i64
}

extern "C" fn less_r(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let node_a = tnr_of(a);
        let node_b = tnr_of(b as *mut bpf_rb_node);

        (*node_a).key < (*node_b).key
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn rbtree_search_kptr_ref(_ctx: *const c_void) -> i64 {
    let lookup_key: i32 = NR_NODES / 2;
    let lookup_data: i32 = NR_NODES / 2;
    let ret: i32;

    unsafe {
        let mut i: i32 = 0;
        while i < NR_NODES && can_loop() {
            let tnode_r = bpf_obj_new(tree_node_ref_id()) as *mut tree_node_ref;
            if tnode_r.is_null() {
                return 167;
            }

            let node_data = bpf_obj_new(node_data_id()) as *mut node_data;
            if node_data.is_null() {
                bpf_obj_drop(tnode_r.cast());
                return 172;
            }

            (*tnode_r).key = i as u64;
            (*node_data).data = i;

            let node_data: *mut node_data =
                bpf_kptr_xchg(addr_of_mut!((*tnode_r).node_data).cast(), node_data.cast()).cast();
            if !node_data.is_null() {
                bpf_obj_drop(node_data.cast());
            }

            // Unused reference
            let tnode_m = bpf_refcount_acquire(tnode_r.cast()) as *mut tree_node_ref;
            if tnode_m.is_null() {
                return 185;
            }

            bpf_spin_lock(addr_of_mut!(lock_r));
            bpf_rbtree_add(addr_of_mut!(root_r), addr_of_mut!((*tnode_r).node), less_r);
            bpf_spin_unlock(addr_of_mut!(lock_r));

            bpf_obj_drop(tnode_m.cast());
            i += 1;
        }

        'fail: {
            bpf_spin_lock(addr_of_mut!(lock_r));
            let mut rb_n = bpf_rbtree_root(addr_of_mut!(root_r));
            while !rb_n.is_null() && can_loop() {
                let tnode_r = tnr_of(rb_n);
                let node_data: *mut node_data =
                    bpf_kptr_xchg(addr_of_mut!((*tnode_r).node_data).cast(), core::ptr::null_mut())
                        .cast();
                if node_data.is_null() {
                    ret = 200;
                    break 'fail;
                }

                let data = (*node_data).data;
                let node_data: *mut node_data =
                    bpf_kptr_xchg(addr_of_mut!((*tnode_r).node_data).cast(), node_data.cast()).cast();
                if !node_data.is_null() {
                    bpf_spin_unlock(addr_of_mut!(lock_r));
                    bpf_obj_drop(node_data.cast());
                    return 209;
                }

                if lookup_key as u64 == (*tnode_r).key {
                    if data == lookup_data {
                        break;
                    }

                    ret = 216;
                    break 'fail;
                }

                if (lookup_key as u64) < (*tnode_r).key {
                    rb_n = bpf_rbtree_left(addr_of_mut!(root_r), rb_n);
                } else {
                    rb_n = bpf_rbtree_right(addr_of_mut!(root_r), rb_n);
                }
            }
            bpf_spin_unlock(addr_of_mut!(lock_r));

            while can_loop() {
                bpf_spin_lock(addr_of_mut!(lock_r));
                let rb_n = bpf_rbtree_first(addr_of_mut!(root_r));
                if rb_n.is_null() {
                    bpf_spin_unlock(addr_of_mut!(lock_r));
                    return 0;
                }

                let rb_n = bpf_rbtree_remove(addr_of_mut!(root_r), rb_n);
                if rb_n.is_null() {
                    ret = 237;
                    break 'fail;
                }
                bpf_spin_unlock(addr_of_mut!(lock_r));

                let tnode_r = tnr_of(rb_n);

                let node_data: *mut node_data =
                    bpf_kptr_xchg(addr_of_mut!((*tnode_r).node_data).cast(), core::ptr::null_mut())
                        .cast();
                if !node_data.is_null() {
                    bpf_obj_drop(node_data.cast());
                }

                bpf_obj_drop(tnode_r.cast());
            }

            return 0;
        }
        bpf_spin_unlock(addr_of_mut!(lock_r));
    }
    ret as i64
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn non_own_ref_kptr_xchg_no_lock(_ctx: *const c_void) -> i64 {
    unsafe {
        bpf_spin_lock(addr_of_mut!(lock));
        let rb_n = bpf_rbtree_first(addr_of_mut!(root));
        if rb_n.is_null() {
            bpf_spin_unlock(addr_of_mut!(lock));
            return 270;
        }
        bpf_spin_unlock(addr_of_mut!(lock));

        let tnode = tn_of(rb_n);
        let node_data: *mut node_data =
            bpf_kptr_xchg(addr_of_mut!((*tnode).node_data).cast(), core::ptr::null_mut()).cast();
        if node_data.is_null() {
            return 277;
        }

        let data = (*node_data).data;
        if data < 0 {
            return 281;
        }

        let node_data: *mut node_data =
            bpf_kptr_xchg(addr_of_mut!((*tnode).node_data).cast(), node_data.cast()).cast();
        if !node_data.is_null() {
            return 285;
        }
    }
    0
}

btf_type_tags! {
    tree_node.node_data: kptr;
    tree_node_ref.node_data: kptr;
}

bpf_object!("GPL");
bpf_rs_core::test_tags! {
    rbtree_search_kptr: __retval("0");
    rbtree_search_kptr_ref: __retval("0");
    non_own_ref_kptr_xchg_no_lock: __failure, __msg("R1 type=scalar expected=map_value, ptr_, ptr_");
}
