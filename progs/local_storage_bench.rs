// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

// Direct translation of tools/testing/selftests/bpf/progs/local_storage_bench.c
// (bpf-rs-core idiom). benchs/bench_local_storage.c creates the inner
// task-storage or hash maps, puts them in the outer array-of-maps, sets
// the `const volatile` .rodata parameters, attaches the fentry program
// and reads `hits`/`important_hits`: each getpgid() does 10000 lookups
// through a bpf_loop callback, each looking an inner map up by index and
// then a task-storage element (or a random hash key) in it. The two
// outer maps' `__array(values, ...)` inner definitions carry no static
// slots: a zero-length array member, as the C's BTF has it. The .rodata
// parameters are re-read at every use, as clang does. The two `%` by a
// .rodata parameter are core::intrinsics::unchecked_rem: Rust's `%` adds a
// division-by-zero panic path (two panic subprograms) that the C's plain
// `w %= w` does not have (BPF defines the remainder by zero: the dividend
// is kept).

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_get_prandom_u32, bpf_loop, bpf_map_lookup_elem,
    bpf_task_storage_get, sync_fetch_and_add,
};

const HASHMAP_SZ: usize = 4194304;
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

#[allow(non_camel_case_types)]
#[repr(C)]
struct inner_task_storage_map {
    r#type: *const [i32; 29], // BPF_MAP_TYPE_TASK_STORAGE
    map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
    key: *const i32,
    value: *const i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct array_of_local_storage_maps_def {
    r#type: *const [i32; 12], // BPF_MAP_TYPE_ARRAY_OF_MAPS
    max_entries: *const [i32; 1000],
    key: *const i32,
    value: *const i32,
    values: [*const inner_task_storage_map; 0],
}
unsafe impl Sync for array_of_local_storage_maps_def {}

#[link_section = ".maps"]
#[no_mangle]
static array_of_local_storage_maps: array_of_local_storage_maps_def = array_of_local_storage_maps_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [],
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct inner_hash_map {
    r#type: *const [i32; 1], // BPF_MAP_TYPE_HASH
    max_entries: *const [i32; HASHMAP_SZ],
    key: *const i32,
    value: *const i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct array_of_hash_maps_def {
    r#type: *const [i32; 12], // BPF_MAP_TYPE_ARRAY_OF_MAPS
    max_entries: *const [i32; 1000],
    key: *const i32,
    value: *const i32,
    values: [*const inner_hash_map; 0],
}
unsafe impl Sync for array_of_hash_maps_def {}

#[link_section = ".maps"]
#[no_mangle]
static array_of_hash_maps: array_of_hash_maps_def = array_of_hash_maps_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [],
};

#[no_mangle]
static mut important_hits: isize = 0;
#[no_mangle]
static mut hits: isize = 0;

/* set from user-space */
#[link_section = ".rodata"]
#[no_mangle]
static use_hashmap: u32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static hashmap_num_keys: u32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static num_maps: u32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static interleave: u32 = 0;

#[allow(non_camel_case_types)]
#[repr(C)]
struct loop_ctx {
    task: *mut c_void,
    loop_hits: isize,
    loop_important_hits: isize,
}

#[inline(always)]
fn do_lookup(elem: u32, lctx: *mut loop_ctx) -> i32 {
    let mut idx: i32 = 0;

    unsafe {
        let map: *const c_void = if read_volatile(addr_of!(use_hashmap)) != 0 {
            addr_of!(array_of_hash_maps) as *const c_void
        } else {
            addr_of!(array_of_local_storage_maps) as *const c_void
        };
        let inner_map = bpf_map_lookup_elem(map, &elem);
        if inner_map.is_null() {
            return -1;
        }

        if read_volatile(addr_of!(use_hashmap)) != 0 {
            idx = core::intrinsics::unchecked_rem(bpf_get_prandom_u32(), read_volatile(addr_of!(hashmap_num_keys))) as i32;
            bpf_map_lookup_elem(inner_map as *const c_void, &idx);
        } else {
            bpf_task_storage_get(
                inner_map as *const c_void,
                (*lctx).task,
                &idx as *const i32 as *const c_void,
                BPF_LOCAL_STORAGE_GET_F_CREATE,
            );
        }

        (*lctx).loop_hits += 1;
        if elem == 0 {
            (*lctx).loop_important_hits += 1;
        }
    }
    0
}

extern "C" fn r#loop(index: u64, lctx: *mut loop_ctx) -> i64 {
    let map_idx = unsafe { core::intrinsics::unchecked_rem(index as u32, read_volatile(addr_of!(num_maps))) };

    do_lookup(map_idx, lctx);
    if unsafe { read_volatile(addr_of!(interleave)) } != 0 && map_idx % 3 == 0 {
        do_lookup(0, lctx);
    }
    0
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn get_local(_ctx: *mut c_void) -> i32 {
    let mut lctx = loop_ctx {
        task: bpf_get_current_task_btf(),
        loop_hits: 0,
        loop_important_hits: 0,
    };

    bpf_loop(10000, r#loop, &mut lctx, 0);
    unsafe {
        sync_fetch_and_add(addr_of_mut!(hits), lctx.loop_hits);
        sync_fetch_and_add(addr_of_mut!(important_hits), lctx.loop_important_hits);
    }
    0
}

bpf_object!("GPL");
