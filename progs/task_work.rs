// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/task_work.c
// (bpf-rs-core idiom). Each perf_event program takes (or creates) the one
// element of its map and schedules task work on the current task; the
// callback copies the user string the test points user_ptr at into the
// element, which prog_tests/test_task_work.c reads back from the map.
// `user_ptr` is the C's `const void *`: a `*mut c_void` is a void pointer in
// BTF (scripts/btf_rename.py)
// BTF_C_VOID: c_void

use core::ffi::c_void;

use bpf_rs_core::helpers::{bpf_get_current_task_btf, bpf_map_lookup_elem, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, bpf_object};

const BPF_NOEXIST: u64 = 1;

#[no_mangle]
static mut user_ptr: *const c_void = core::ptr::null();

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_task_work {
    __opaque: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct elem {
    data: [i8; 128],
    tw: bpf_task_work,
}

bpf_map! {
    hmap {
        r#type: *const [i32; maps::HASH],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const elem,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static arrmap: BpfMap<i32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static lrumap: BpfMap<i32, elem, { maps::LRU_HASH }, 1> = BpfMap::new();

type WorkFn = extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;

extern "C" {
    fn bpf_copy_from_user_str(dst: *mut c_void, dst__sz: u32, unsafe_ptr: *const c_void, flags: u64) -> i32;
    fn bpf_task_work_schedule_resume(task: *mut c_void, tw: *mut c_void, map: *mut c_void, callback: WorkFn) -> i32;
    fn bpf_task_work_schedule_signal(task: *mut c_void, tw: *mut c_void, map: *mut c_void, callback: WorkFn) -> i32;
}

extern "C" fn process_work(_map: *mut c_void, _key: *mut c_void, value: *mut c_void) -> i32 {
    let work = value as *mut elem;

    unsafe {
        bpf_copy_from_user_str(core::ptr::addr_of_mut!((*work).data) as *mut c_void, 128, user_ptr, 0);
    }
    0
}

#[no_mangle]
static mut key: i32 = 0;

#[inline(always)]
fn key_ref() -> &'static i32 {
    unsafe { &*core::ptr::addr_of!(key) }
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn oncpu_hash_map(_args: *const c_void) -> i32 {
    let empty_work: elem = unsafe { core::mem::zeroed() };

    let task: *mut c_void = bpf_get_current_task_btf();
    let err = bpf_map_update_elem(&hmap, key_ref(), &empty_work, BPF_NOEXIST);
    if err != 0 {
        return 0;
    }
    let work = bpf_map_lookup_elem(&hmap, key_ref()) as *mut elem;
    if work.is_null() {
        return 0;
    }
    unsafe {
        bpf_task_work_schedule_resume(
            task,
            core::ptr::addr_of_mut!((*work).tw) as *mut c_void,
            &hmap as *const _ as *mut c_void,
            process_work,
        );
    }
    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn oncpu_array_map(_args: *const c_void) -> i32 {
    let task: *mut c_void = bpf_get_current_task_btf();
    let work = bpf_map_lookup_elem(&arrmap, key_ref()) as *mut elem;
    if work.is_null() {
        return 0;
    }
    unsafe {
        bpf_task_work_schedule_signal(
            task,
            core::ptr::addr_of_mut!((*work).tw) as *mut c_void,
            &arrmap as *const _ as *mut c_void,
            process_work,
        );
    }
    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn oncpu_lru_map(_args: *const c_void) -> i32 {
    let empty_work: elem = unsafe { core::mem::zeroed() };

    let task: *mut c_void = bpf_get_current_task_btf();
    let work = bpf_map_lookup_elem(&lrumap, key_ref()) as *mut elem;
    if !work.is_null() {
        return 0;
    }
    let err = bpf_map_update_elem(&lrumap, key_ref(), &empty_work, BPF_NOEXIST);
    if err != 0 {
        return 0;
    }
    let work = bpf_map_lookup_elem(&lrumap, key_ref()) as *mut elem;
    if work.is_null() || unsafe { (*work).data[0] } != 0 {
        return 0;
    }
    unsafe {
        bpf_task_work_schedule_resume(
            task,
            core::ptr::addr_of_mut!((*work).tw) as *mut c_void,
            &lrumap as *const _ as *mut c_void,
            process_work,
        );
    }
    0
}

bpf_object!("GPL");
