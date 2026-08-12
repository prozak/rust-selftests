#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_map_lookup_elem};

// struct inner_array_type { __uint(type, ARRAY); __uint(map_flags,
// BPF_F_MMAPABLE); __type(key, __u32); __type(value, __u64);
// __uint(max_entries, 1); }
#[allow(non_camel_case_types)]
#[repr(C)]
struct inner_array_type {
    r#type: *const [i32; 2],        // BPF_MAP_TYPE_ARRAY
    map_flags: *const [i32; 1024],  // BPF_F_MMAPABLE
    key: *const u32,
    value: *const u64,
    max_entries: *const [i32; 1],
}
unsafe impl Sync for inner_array_type {}

#[link_section = ".maps"]
#[no_mangle]
static inner_array: inner_array_type = inner_array_type {
    r#type: core::ptr::null(),
    map_flags: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
};

// struct { __uint(type, HASH_OF_MAPS); __uint(key_size, 4);
// __uint(value_size, 4); __uint(max_entries, 1); __array(values, struct
// inner_array_type); } — no static initializer for `values`, the userspace
// test populates the outer map's single slot at runtime via
// bpf_map__update_elem, so the zero-length-array encoding is unaffected by
// the flexible-array-member static-init limitation.
#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_map_def {
    r#type: *const [i32; 13], // BPF_MAP_TYPE_HASH_OF_MAPS
    key_size: *const [i32; 4],
    value_size: *const [i32; 4],
    max_entries: *const [i32; 1],
    values: [*const inner_array_type; 0],
}
unsafe impl Sync for outer_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_map: outer_map_def = outer_map_def {
    r#type: core::ptr::null(),
    key_size: core::ptr::null(),
    value_size: core::ptr::null(),
    max_entries: core::ptr::null(),
    values: [],
};

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut match_value: u64 = 0x13572468;
#[no_mangle]
// translint: allow(bool-global) — equivalence prover confirms EQUIV: the C
// object compiles `if (done)` as `jne 0`, matching Rust's `if done`.
static mut done: bool = false;
#[no_mangle]
static mut pid_match: bool = false;
#[no_mangle]
static mut outer_map_match: bool = false;

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn add_to_list_in_inner_array(_ctx: *const core::ffi::c_void) -> i32 {
    let curr_pid = bpf_get_current_pid_tgid() as u32;

    if unsafe { done } || curr_pid as i32 != unsafe { pid } {
        return 0;
    }

    unsafe { pid_match = true };

    let map = bpf_map_lookup_elem(&outer_map, &curr_pid);
    if map.is_null() {
        return 0;
    }

    unsafe { outer_map_match = true };

    let zero: u32 = 0;
    let value = bpf_map_lookup_elem(map as *const core::ffi::c_void, &zero) as *mut u64;
    if value.is_null() {
        return 0;
    }

    unsafe {
        *value = match_value;
        done = true;
    }
    0
}

bpf_object!("GPL");
