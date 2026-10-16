// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/rbtree.c
// (bpf-rs-core idiom).
//
// glock, groot, groot_array, groot_array_one (private(A)) and groot_nested
// (private(B)) are C `__hidden` statics in SEC(".data.A"/".data.B"), so
// BTF_VAR_STATIC and the maps are not mmapped by libbpf. A private Rust
// static (no #[no_mangle]) gets the same linkage (see test_spin_lock.rs);
// rust-bpf's #[btf_tag] still finds it by its debug-info name and puts C's
// __contains(node_data, node) decl tag on it, on the array statics too, and
// on root_nested_inner.root as a member tag. bpf_obj_new() takes
// node_data's local type id like C's bpf_obj_new(typeof(*n)).

// BTF_TYPE_ID: node_data_id local struct node_data

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_spin_lock, bpf_spin_unlock};
use btf_macros::btf_tag;
use core::ffi::c_void;

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

#[allow(non_camel_case_types)]
#[btf_tag]
#[repr(C)]
struct root_nested_inner {
    glock: bpf_spin_lock,
    #[btf_tag(decl_tag = "contains:node_data:node")]
    root: bpf_rb_root,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct root_nested {
    inner: root_nested_inner,
}

#[no_mangle]
static mut less_callback_ran: i64 = -1;
#[no_mangle]
static mut removed_key: i64 = -1;
#[no_mangle]
static mut first_data: [i64; 2] = [-1, -1];

#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut glock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:node")]
#[link_section = ".data.A"]
static mut groot: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:node")]
#[link_section = ".data.A"]
static mut groot_array: [bpf_rb_root; 2] =
    [bpf_rb_root { __opaque: [0; 2] }, bpf_rb_root { __opaque: [0; 2] }];

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_data:node")]
#[link_section = ".data.A"]
static mut groot_array_one: [bpf_rb_root; 1] = [bpf_rb_root { __opaque: [0; 2] }];

#[allow(non_upper_case_globals)]
#[link_section = ".data.B"]
static mut groot_nested: root_nested = root_nested {
    inner: root_nested_inner {
        glock: bpf_spin_lock { val: 0 },
        root: bpf_rb_root { __opaque: [0; 2] },
    },
};

extern "C" {
    fn node_data_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_rbtree_add(
        root: *mut bpf_rb_root,
        node: *mut bpf_rb_node,
        less: extern "C" fn(*mut bpf_rb_node, *const bpf_rb_node) -> bool,
    ) -> i32;
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
        less_callback_ran = 1;

        (*node_a).key < (*node_b).key
    }
}

unsafe fn __add_three(root: *mut bpf_rb_root, lock: *mut bpf_spin_lock) -> i64 {
    let n = bpf_obj_new(node_data_id()) as *mut node_data;
    if n.is_null() {
        return 1;
    }
    (*n).key = 5;

    let m = bpf_obj_new(node_data_id()) as *mut node_data;
    if m.is_null() {
        bpf_obj_drop(n.cast());
        return 2;
    }
    (*m).key = 1;

    bpf_spin_lock(lock);
    bpf_rbtree_add(root, core::ptr::addr_of_mut!((*n).node), less);
    bpf_rbtree_add(root, core::ptr::addr_of_mut!((*m).node), less);
    bpf_spin_unlock(lock);

    let n = bpf_obj_new(node_data_id()) as *mut node_data;
    if n.is_null() {
        return 3;
    }
    (*n).key = 3;

    bpf_spin_lock(lock);
    bpf_rbtree_add(root, core::ptr::addr_of_mut!((*n).node), less);
    bpf_spin_unlock(lock);
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_add_nodes(_ctx: *const c_void) -> i64 {
    unsafe { __add_three(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!(glock)) }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_add_nodes_nested(_ctx: *const c_void) -> i64 {
    unsafe {
        __add_three(
            core::ptr::addr_of_mut!(groot_nested.inner.root),
            core::ptr::addr_of_mut!(groot_nested.inner.glock),
        )
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_add_and_remove(_ctx: *const c_void) -> i64 {
    unsafe {
        let mut m: *mut node_data = core::ptr::null_mut();

        'err_out: {
            let n = bpf_obj_new(node_data_id()) as *mut node_data;
            if n.is_null() {
                break 'err_out;
            }
            (*n).key = 5;

            m = bpf_obj_new(node_data_id()) as *mut node_data;
            if m.is_null() {
                bpf_obj_drop(n.cast());
                return 1;
            }
            (*m).key = 3;

            bpf_spin_lock(core::ptr::addr_of_mut!(glock));
            bpf_rbtree_add(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!((*n).node), less);
            bpf_rbtree_add(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!((*m).node), less);
            let res = bpf_rbtree_remove(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!((*n).node));
            bpf_spin_unlock(core::ptr::addr_of_mut!(glock));

            if res.is_null() {
                return 1;
            }

            let n = entry(res);
            removed_key = (*n).key;
            bpf_obj_drop(n.cast());

            return 0;
        }
        // err_out: n is NULL here; m was not allocated yet either
        if !m.is_null() {
            bpf_obj_drop(m.cast());
        }
        1
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_add_and_remove_array(_ctx: *const c_void) -> i64 {
    unsafe {
        let mut nodes: [[*mut node_data; 2]; 3] = [[core::ptr::null_mut(); 2]; 3];
        let mut k1: i64 = -1;
        let mut k2: i64 = -1;
        let mut k3: i64 = -1;

        'err_out: {
            let mut i = 0;
            while i < 3 {
                let mut j = 0;
                while j < 2 {
                    let n = bpf_obj_new(node_data_id()) as *mut node_data;
                    nodes[i][j] = n;
                    if n.is_null() {
                        break 'err_out;
                    }
                    (*n).key = (i * 2 + j) as i64;
                    j += 1;
                }
                i += 1;
            }

            bpf_spin_lock(core::ptr::addr_of_mut!(glock));
            let mut i = 0;
            while i < 2 {
                let mut j = 0;
                while j < 2 {
                    bpf_rbtree_add(
                        core::ptr::addr_of_mut!(groot_array[i]),
                        core::ptr::addr_of_mut!((*nodes[i][j]).node),
                        less,
                    );
                    j += 1;
                }
                i += 1;
            }
            let mut j = 0;
            while j < 2 {
                bpf_rbtree_add(
                    core::ptr::addr_of_mut!(groot_array_one[0]),
                    core::ptr::addr_of_mut!((*nodes[2][j]).node),
                    less,
                );
                j += 1;
            }
            let res1 = bpf_rbtree_remove(
                core::ptr::addr_of_mut!(groot_array[0]),
                core::ptr::addr_of_mut!((*nodes[0][0]).node),
            );
            let res2 = bpf_rbtree_remove(
                core::ptr::addr_of_mut!(groot_array[1]),
                core::ptr::addr_of_mut!((*nodes[1][0]).node),
            );
            let res3 = bpf_rbtree_remove(
                core::ptr::addr_of_mut!(groot_array_one[0]),
                core::ptr::addr_of_mut!((*nodes[2][0]).node),
            );
            bpf_spin_unlock(core::ptr::addr_of_mut!(glock));

            if !res1.is_null() {
                let n = entry(res1);
                k1 = (*n).key;
                bpf_obj_drop(n.cast());
            }
            if !res2.is_null() {
                let n = entry(res2);
                k2 = (*n).key;
                bpf_obj_drop(n.cast());
            }
            if !res3.is_null() {
                let n = entry(res3);
                k3 = (*n).key;
                bpf_obj_drop(n.cast());
            }
            if k1 != 0 || k2 != 2 || k3 != 4 {
                return 2;
            }

            return 0;
        }

        let mut i = 0;
        while i < 3 {
            let mut j = 0;
            while j < 2 {
                if !nodes[i][j].is_null() {
                    bpf_obj_drop(nodes[i][j].cast());
                }
                j += 1;
            }
            i += 1;
        }
        1
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_first_and_remove(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return 1;
        }
        (*n).key = 3;
        (*n).data = 4;

        // err_out: drop what was allocated (C's `if (n)` / `if (m)` tests)
        let m = bpf_obj_new(node_data_id()) as *mut node_data;
        if m.is_null() {
            bpf_obj_drop(n.cast());
            return 1;
        }
        (*m).key = 5;
        (*m).data = 6;

        let o = bpf_obj_new(node_data_id()) as *mut node_data;
        if o.is_null() {
            bpf_obj_drop(n.cast());
            bpf_obj_drop(m.cast());
            return 1;
        }
        (*o).key = 1;
        (*o).data = 2;
        {

            bpf_spin_lock(core::ptr::addr_of_mut!(glock));
            bpf_rbtree_add(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!((*n).node), less);
            bpf_rbtree_add(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!((*m).node), less);
            bpf_rbtree_add(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!((*o).node), less);

            let res = bpf_rbtree_first(core::ptr::addr_of_mut!(groot));
            if res.is_null() {
                bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
                return 2;
            }

            let o = entry(res);
            first_data[0] = (*o).data;

            let res = bpf_rbtree_remove(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!((*o).node));
            bpf_spin_unlock(core::ptr::addr_of_mut!(glock));

            if res.is_null() {
                return 5;
            }

            let o = entry(res);
            removed_key = (*o).key;
            bpf_obj_drop(o.cast());

            bpf_spin_lock(core::ptr::addr_of_mut!(glock));
            let res = bpf_rbtree_first(core::ptr::addr_of_mut!(groot));
            if res.is_null() {
                bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
                return 3;
            }

            let o = entry(res);
            first_data[1] = (*o).data;
            bpf_spin_unlock(core::ptr::addr_of_mut!(glock));

            0
        }
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_api_release_aliasing(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            return 1;
        }
        (*n).key = 41;
        (*n).data = 42;

        bpf_spin_lock(core::ptr::addr_of_mut!(glock));
        bpf_rbtree_add(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!((*n).node), less);
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock));

        bpf_spin_lock(core::ptr::addr_of_mut!(glock));

        'err_out: {
            // m and o point to the same node, but the verifier doesn't know
            let res = bpf_rbtree_first(core::ptr::addr_of_mut!(groot));
            if res.is_null() {
                break 'err_out;
            }
            let o = entry(res);

            let res = bpf_rbtree_first(core::ptr::addr_of_mut!(groot));
            if res.is_null() {
                break 'err_out;
            }
            let m = entry(res);

            let res = bpf_rbtree_remove(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!((*m).node));
            // The previous remove returned an owning reference to m, the
            // same node non-owning ref o points at; the second remove
            // returns NULL at runtime since the node is no longer in a tree.
            let res2 = bpf_rbtree_remove(core::ptr::addr_of_mut!(groot), core::ptr::addr_of_mut!((*o).node));

            bpf_spin_unlock(core::ptr::addr_of_mut!(glock));

            if !res.is_null() {
                let o = entry(res);
                first_data[0] = (*o).data;
                bpf_obj_drop(o.cast());
            }
            if !res2.is_null() {
                // the second remove fails, so this doesn't execute
                let m = entry(res2);
                first_data[1] = (*m).data;
                bpf_obj_drop(m.cast());
            }
            return 0;
        }

        bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
        1
    }
}

bpf_object!("GPL");
