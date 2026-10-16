// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/map_in_map_btf.c
// (bpf-rs-core idiom).
//
// The inner array's value holds a bpf_list_head the kernel only accepts with
// C's __contains(node_data, node): the decl tag "contains:node_data:node" on
// member 0 of map_value, emitted by rust-bpf's #[btf_tag]. bpf_obj_new()
// takes node_data's local type id like C's bpf_obj_new(typeof(*new)).

// BTF_TYPE_ID: node_data_id local struct node_data

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock,
};
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
    data: u64,
    node: bpf_list_node,
}

#[allow(non_camel_case_types)]
#[btf_tag]
#[repr(C)]
struct map_value {
    #[btf_tag(decl_tag = "contains:node_data:node")]
    head: bpf_list_head,
    lock: bpf_spin_lock,
}

// struct inner_array_type { __uint(type, ARRAY); __type(key, int);
// __type(value, struct map_value); __uint(max_entries, 1); } inner_array
#[allow(non_camel_case_types)]
#[repr(C)]
struct inner_array_type {
    r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY
    key: *const i32,
    value: *const map_value,
    max_entries: *const [i32; 1],
}
unsafe impl Sync for inner_array_type {}

#[link_section = ".maps"]
#[no_mangle]
static inner_array: inner_array_type = inner_array_type {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
};

// struct { __uint(type, ARRAY_OF_MAPS); __uint(key_size, 4);
// __uint(value_size, 4); __uint(max_entries, 1);
// __array(values, struct inner_array_type); } outer_array = {
//     .values = { [0] = &inner_array } };
//
// `[T; 1]` emits the slot storage and its .rel.maps entry;
// scripts/btf_map_slots.py rewrites the BTF member to the zero-length array
// libbpf demands.
#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_array_def {
    r#type: *const [i32; 12], // BPF_MAP_TYPE_ARRAY_OF_MAPS
    key_size: *const [i32; 4],
    value_size: *const [i32; 4],
    max_entries: *const [i32; 1],
    values: [*const inner_array_type; 1],
}
unsafe impl Sync for outer_array_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_array: outer_array_def = outer_array_def {
    r#type: core::ptr::null(),
    key_size: core::ptr::null(),
    value_size: core::ptr::null(),
    max_entries: core::ptr::null(),
    values: [&inner_array],
};

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
// translint: allow(bool-global) — the C object tests `done` with `jne 0`
// (`if (done || ...)`), which is what Rust's `if done` compiles to.
static mut done: bool = false;

extern "C" {
    fn node_data_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_list_push_back(head: *mut bpf_list_head, node: *mut bpf_list_node) -> i32;
}

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn add_to_list_in_inner_array(_ctx: *const c_void) -> i32 {
    if unsafe { done } || bpf_get_current_pid_tgid() as u32 != unsafe { pid } as u32 {
        return 0;
    }

    let zero: i32 = 0;
    let map = bpf_map_lookup_elem(&outer_array, &zero);
    if map.is_null() {
        return 0;
    }

    let value = bpf_map_lookup_elem(map, &zero) as *mut map_value;
    if value.is_null() {
        return 0;
    }

    let new = unsafe { bpf_obj_new(node_data_id()) } as *mut node_data;
    if new.is_null() {
        return 0;
    }

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*value).lock));
        bpf_list_push_back(
            core::ptr::addr_of_mut!((*value).head),
            core::ptr::addr_of_mut!((*new).node),
        );
        bpf_spin_unlock(core::ptr::addr_of_mut!((*value).lock));
        done = true;
    }

    0
}

bpf_object!("GPL");
