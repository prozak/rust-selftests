// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/local_kptr_stash_fail.c,
// bpf-rs-core idiom (local_kptr_stash.rs is the positive counterpart).
//
// Two NEGATIVE verifier tests (prog_tests/local_kptr_stash.c RUN_TESTS this
// object): stashing a node_data2 allocation into a map_value's node_data
// __kptr slot (the kptr type tag is declared with btf_type_tags!), and
// bpf_obj_drop() of a pointer into the middle of an allocation (its
// bpf_rb_node member). C's bpf_obj_new(typeof(*p)) / bpf_obj_drop(p) are
// the two-argument _impl kfuncs with the local type id imported by the
// BTF_TYPE_ID markers; the just_here_because_btf_bug global keeps the full
// node_data struct in BTF as the C comment explains.

use bpf_rs_core::helpers::{bpf_kptr_xchg, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, btf_type_tags, test_tags};
use core::ffi::c_void;
use core::ptr::addr_of_mut;

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
#[repr(C)]
struct map_value {
    node: *mut node_data,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct node_data2 {
    key: [i64; 4],
}

#[no_mangle]
static mut just_here_because_btf_bug: *mut node_data = core::ptr::null_mut();

#[link_section = ".maps"]
#[no_mangle]
static some_nodes: BpfMap<i32, map_value, { maps::ARRAY }, 2> = BpfMap::new();

// BTF_TYPE_ID: node_data_id local struct node_data
// BTF_TYPE_ID: node_data2_id local struct node_data2
extern "C" {
    fn node_data_id() -> u64;
    fn node_data2_id() -> u64;
    fn bpf_obj_new_impl(local_type_id: u64, meta: *mut c_void) -> *mut c_void;
    fn bpf_obj_drop_impl(obj: *mut c_void, meta: *mut c_void);
}

test_tags! {
    stash_rb_nodes: __failure, __msg("invalid kptr access, R2 type=ptr_node_data2 expected=ptr_node_data");
    drop_rb_node_off: __failure, __msg("R1 must have zero offset when passed to release func");
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn stash_rb_nodes(_ctx: *mut c_void) -> i64 {
    let idx: i32 = 0;

    let mapval = bpf_map_lookup_elem(&some_nodes, &idx) as *mut map_value;
    if mapval.is_null() {
        return 1;
    }

    let res = unsafe { bpf_obj_new_impl(node_data2_id(), core::ptr::null_mut()) } as *mut node_data2;
    if res.is_null() {
        return 1;
    }
    unsafe { (*res).key[0] = 40 };

    let res = unsafe { bpf_kptr_xchg(addr_of_mut!((*mapval).node).cast(), res.cast()) } as *mut node_data2;
    if !res.is_null() {
        unsafe { bpf_obj_drop_impl(res.cast(), core::ptr::null_mut()) };
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn drop_rb_node_off(_ctx: *mut c_void) -> i64 {
    let idx: i32 = 0;

    let mapval = bpf_map_lookup_elem(&some_nodes, &idx) as *mut map_value;
    if mapval.is_null() {
        return 1;
    }

    let res = unsafe { bpf_obj_new_impl(node_data_id(), core::ptr::null_mut()) } as *mut node_data;
    if res.is_null() {
        return 1;
    }
    /* Try releasing with graph node offset */
    unsafe { bpf_obj_drop_impl(addr_of_mut!((*res).node).cast(), core::ptr::null_mut()) };
    0
}

btf_type_tags! {
    map_value.node: kptr;
}

bpf_object!("GPL");
