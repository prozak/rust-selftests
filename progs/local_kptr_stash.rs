// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/local_kptr_stash.c
// (bpf-rs-core idiom).
//
// Four local types are allocated with bpf_obj_new(), each through its own
// `// BTF_TYPE_ID:` extern like C's bpf_obj_new(typeof(*p)). The __kptr
// members (map values, node_data, stash) are declared with btf_type_tags!
// at the bottom; local_with_root.r carries C's __contains(node_data, node)
// as a member decl tag through rust-bpf's #[btf_tag]. prog_test_ref_kfunc
// is bpf_testmod's type, opaque here as in jit_probe_mem.rs.

// BTF_TYPE_ID: plain_local_id local struct plain_local
// BTF_TYPE_ID: node_data_id local struct node_data
// BTF_TYPE_ID: local_with_root_id local struct local_with_root
// BTF_TYPE_ID: refcounted_node_id local struct refcounted_node

use bpf_rs_core::helpers::{bpf_kptr_xchg, bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, btf_type_tags};
use btf_macros::btf_tag;
use core::ffi::c_void;
use core::ptr::addr_of_mut;

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
struct prog_test_ref_kfunc {
    _opaque: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct node_data {
    key: i64,
    data: i64,
    stashed_in_local_kptr: *mut plain_local,
    node: bpf_rb_node,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct refcounted_node {
    data: i64,
    rb_node: bpf_rb_node,
    refcount: bpf_refcount,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct stash {
    l: bpf_spin_lock,
    stashed: *mut refcounted_node,
}

#[link_section = ".maps"]
#[no_mangle]
static refcounted_node_stash: BpfMap<i32, stash, { maps::ARRAY }, 10> = BpfMap::new();

#[allow(non_camel_case_types)]
#[repr(C)]
struct plain_local {
    key: i64,
    data: i64,
}

#[allow(non_camel_case_types)]
#[btf_tag]
#[repr(C)]
struct local_with_root {
    key: i64,
    l: bpf_spin_lock,
    #[btf_tag(decl_tag = "contains:node_data:node")]
    r: bpf_rb_root,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_value {
    not_kptr: *mut prog_test_ref_kfunc,
    val: *mut prog_test_ref_kfunc,
    node: *mut node_data,
    plain: *mut plain_local,
    local_root: *mut local_with_root,
}

// C keeps these two globals so that LLVM emits node_data's and
// refcounted_node's full BTF rather than a forward declaration.
#[no_mangle]
static mut just_here_because_btf_bug: *mut node_data = core::ptr::null_mut();
#[no_mangle]
static mut just_here_because_btf_bug2: *mut refcounted_node = core::ptr::null_mut();

#[link_section = ".maps"]
#[no_mangle]
static some_nodes: BpfMap<i32, map_value, { maps::ARRAY }, 2> = BpfMap::new();

extern "C" {
    fn plain_local_id() -> u64;
    fn node_data_id() -> u64;
    fn local_with_root_id() -> u64;
    fn refcounted_node_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_refcount_acquire(obj: *mut c_void) -> *mut c_void;
    fn bpf_rbtree_add(
        root: *mut bpf_rb_root,
        node: *mut bpf_rb_node,
        less: extern "C" fn(*mut bpf_rb_node, *const bpf_rb_node) -> bool,
    ) -> i32;
    fn bpf_kfunc_call_test_release(p: *mut prog_test_ref_kfunc);
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

unsafe fn create_and_stash(idx: i32, val: i32) -> i32 {
    let mapval = bpf_map_lookup_elem(&some_nodes, &idx) as *mut map_value;
    if mapval.is_null() {
        return 1;
    }

    let inner_local_kptr = bpf_obj_new(plain_local_id()) as *mut plain_local;
    if inner_local_kptr.is_null() {
        return 2;
    }

    let res = bpf_obj_new(node_data_id()) as *mut node_data;
    if res.is_null() {
        bpf_obj_drop(inner_local_kptr.cast());
        return 3;
    }
    (*res).key = val as i64;

    let inner_local_kptr: *mut plain_local = bpf_kptr_xchg(
        addr_of_mut!((*res).stashed_in_local_kptr).cast(),
        inner_local_kptr.cast(),
    )
    .cast();
    if !inner_local_kptr.is_null() {
        // Should never happen, we just obj_new'd res
        bpf_obj_drop(inner_local_kptr.cast());
        bpf_obj_drop(res.cast());
        return 4;
    }

    let res: *mut node_data = bpf_kptr_xchg(addr_of_mut!((*mapval).node).cast(), res.cast()).cast();
    if !res.is_null() {
        bpf_obj_drop(res.cast());
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn stash_rb_nodes(_ctx: *const c_void) -> i64 {
    unsafe {
        let ret = create_and_stash(0, 41);
        if ret != 0 {
            return ret as i64;
        }
        create_and_stash(1, 42) as i64
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn stash_plain(_ctx: *const c_void) -> i64 {
    let idx: i32 = 0;

    unsafe {
        let mapval = bpf_map_lookup_elem(&some_nodes, &idx) as *mut map_value;
        if mapval.is_null() {
            return 1;
        }

        let res = bpf_obj_new(plain_local_id()) as *mut plain_local;
        if res.is_null() {
            return 1;
        }
        (*res).key = 41;

        let res: *mut plain_local =
            bpf_kptr_xchg(addr_of_mut!((*mapval).plain).cast(), res.cast()).cast();
        if !res.is_null() {
            bpf_obj_drop(res.cast());
        }
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn stash_local_with_root(_ctx: *const c_void) -> i64 {
    let idx: i32 = 0;

    unsafe {
        let mapval = bpf_map_lookup_elem(&some_nodes, &idx) as *mut map_value;
        if mapval.is_null() {
            return 1;
        }

        let res = bpf_obj_new(local_with_root_id()) as *mut local_with_root;
        if res.is_null() {
            return 2;
        }
        (*res).key = 41;

        let n = bpf_obj_new(node_data_id()) as *mut node_data;
        if n.is_null() {
            bpf_obj_drop(res.cast());
            return 3;
        }

        bpf_spin_lock(addr_of_mut!((*res).l));
        bpf_rbtree_add(addr_of_mut!((*res).r), addr_of_mut!((*n).node), less);
        bpf_spin_unlock(addr_of_mut!((*res).l));

        let res: *mut local_with_root =
            bpf_kptr_xchg(addr_of_mut!((*mapval).local_root).cast(), res.cast()).cast();
        if !res.is_null() {
            bpf_obj_drop(res.cast());
            return 4;
        }
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn unstash_rb_node(_ctx: *const c_void) -> i64 {
    let key: i32 = 1;

    unsafe {
        let mapval = bpf_map_lookup_elem(&some_nodes, &key) as *mut map_value;
        if mapval.is_null() {
            return 1;
        }

        let res: *mut node_data =
            bpf_kptr_xchg(addr_of_mut!((*mapval).node).cast(), core::ptr::null_mut()).cast();
        if !res.is_null() {
            let inner_local_kptr: *mut plain_local = bpf_kptr_xchg(
                addr_of_mut!((*res).stashed_in_local_kptr).cast(),
                core::ptr::null_mut(),
            )
            .cast();
            if inner_local_kptr.is_null() {
                bpf_obj_drop(res.cast());
                return 1;
            }
            bpf_obj_drop(inner_local_kptr.cast());

            let retval = (*res).key;
            bpf_obj_drop(res.cast());
            return retval;
        }
    }
    1
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn stash_test_ref_kfunc(_ctx: *const c_void) -> i64 {
    let key: i32 = 0;

    unsafe {
        let mapval = bpf_map_lookup_elem(&some_nodes, &key) as *mut map_value;
        if mapval.is_null() {
            return 1;
        }

        let res: *mut prog_test_ref_kfunc =
            bpf_kptr_xchg(addr_of_mut!((*mapval).val).cast(), core::ptr::null_mut()).cast();
        if !res.is_null() {
            bpf_kfunc_call_test_release(res);
        }
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn refcount_acquire_without_unstash(_ctx: *const c_void) -> i64 {
    let mut ret: i32 = 0;

    unsafe {
        let s = bpf_map_lookup_elem(&refcounted_node_stash, &ret) as *mut stash;
        if s.is_null() {
            return 1;
        }

        if (*s).stashed.is_null() {
            // refcount_acquire failure is expected when no refcounted_node
            // has been stashed before this program executes
            return 2;
        }

        let p = bpf_refcount_acquire((*s).stashed.cast()) as *mut refcounted_node;
        if p.is_null() {
            return 3;
        }

        ret = if !(*s).stashed.is_null() { (*(*s).stashed).data as i32 } else { -1 };
        bpf_obj_drop(p.cast());
    }
    ret as i64
}

// Helper for refcount_acquire_without_unstash test
#[link_section = "tc"]
#[no_mangle]
extern "C" fn stash_refcounted_node(_ctx: *const c_void) -> i64 {
    let key: i32 = 0;

    unsafe {
        let s = bpf_map_lookup_elem(&refcounted_node_stash, &key) as *mut stash;
        if s.is_null() {
            return 1;
        }

        let p = bpf_obj_new(refcounted_node_id()) as *mut refcounted_node;
        if p.is_null() {
            return 2;
        }
        (*p).data = 42;

        let p: *mut refcounted_node =
            bpf_kptr_xchg(addr_of_mut!((*s).stashed).cast(), p.cast()).cast();
        if !p.is_null() {
            bpf_obj_drop(p.cast());
            return 3;
        }
    }
    0
}

btf_type_tags! {
    node_data.stashed_in_local_kptr: kptr;
    stash.stashed: kptr;
    map_value.val: kptr;
    map_value.node: kptr;
    map_value.plain: kptr;
    map_value.local_root: kptr;
}

bpf_object!("GPL");
