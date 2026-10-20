// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/task_work_fail.c,
// bpf-rs-core idiom (task_work.rs is the positive counterpart).
//
// Four NEGATIVE verifier tests on bpf_task_work_schedule_resume's arguments
// (prog_tests/test_task_work.c RUN_TESTS this object): a bpf_task_work
// from one map with another map as the owner, a bpf_task_work on the
// stack, a NULL bpf_task_work, and a NULL map.

use bpf_rs_core::helpers::{bpf_get_current_task_btf, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;
use core::ptr::addr_of_mut;

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

type WorkFn = extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;

extern "C" {
    fn bpf_copy_from_user_str(dst: *mut c_void, dst__sz: u32, unsafe_ptr: *const c_void, flags: u64) -> i32;
    fn bpf_task_work_schedule_resume(task: *mut c_void, tw: *mut c_void, map: *mut c_void, callback: WorkFn) -> i32;
}

extern "C" fn process_work(_map: *mut c_void, _key: *mut c_void, value: *mut c_void) -> i32 {
    let work = value as *mut elem;

    unsafe {
        bpf_copy_from_user_str(addr_of_mut!((*work).data) as *mut c_void, 128, user_ptr, 0);
    }
    0
}

#[no_mangle]
static mut key: i32 = 0;

#[inline(always)]
fn key_ref() -> &'static i32 {
    unsafe { &*core::ptr::addr_of!(key) }
}

test_tags! {
    mismatch_map: __failure, __msg("doesn't match map pointer in R3");
    no_map_task_work: __failure, __msg("R2 type=fp expected=map_value");
    task_work_null: __failure, __msg("Possibly NULL pointer passed to trusted R2");
    map_null: __failure, __msg("Possibly NULL pointer passed to trusted R3");
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn mismatch_map(_args: *const c_void) -> i32 {
    let task: *mut c_void = bpf_get_current_task_btf();
    let work = bpf_map_lookup_elem(&arrmap, key_ref()) as *mut elem;
    if work.is_null() {
        return 0;
    }
    unsafe {
        bpf_task_work_schedule_resume(task, addr_of_mut!((*work).tw) as *mut c_void, &hmap as *const _ as *mut c_void, process_work);
    }
    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn no_map_task_work(_args: *const c_void) -> i32 {
    let mut tw = bpf_task_work { __opaque: 0 };

    let task: *mut c_void = bpf_get_current_task_btf();
    unsafe {
        bpf_task_work_schedule_resume(task, &mut tw as *mut bpf_task_work as *mut c_void, &hmap as *const _ as *mut c_void, process_work);
    }
    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn task_work_null(_args: *const c_void) -> i32 {
    let task: *mut c_void = bpf_get_current_task_btf();
    unsafe {
        bpf_task_work_schedule_resume(task, core::ptr::null_mut(), &hmap as *const _ as *mut c_void, process_work);
    }
    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn map_null(_args: *const c_void) -> i32 {
    let task: *mut c_void = bpf_get_current_task_btf();
    let work = bpf_map_lookup_elem(&arrmap, key_ref()) as *mut elem;
    if work.is_null() {
        return 0;
    }
    unsafe {
        bpf_task_work_schedule_resume(task, addr_of_mut!((*work).tw) as *mut c_void, core::ptr::null_mut(), process_work);
    }
    0
}

bpf_object!("GPL");
