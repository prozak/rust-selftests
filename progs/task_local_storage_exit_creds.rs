#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/task_local_storage_exit_creds.c
// (bpf-rs-core idiom).

use bpf_rs_core::helpers::{bpf_task_storage_get, sync_fetch_and_add_u32};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};
use core::ffi::c_void;

bpf_map! {
    task_storage {
        r#type: *const [i32; 29],   // BPF_MAP_TYPE_TASK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const u64,
    }
}

#[no_mangle]
static mut run_count: u32 = 0;
#[no_mangle]
static mut valid_ptr_count: u32 = 0;
#[no_mangle]
static mut null_ptr_count: u32 = 0;

#[link_section = "fentry/exit_creds"]
#[no_mangle]
extern "C" fn trace_exit_creds(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut c_void;

    let ptr = bpf_task_storage_get(&task_storage, task, core::ptr::null_mut(), 1);
    if !ptr.is_null() {
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!(valid_ptr_count), 1);
    } else {
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!(null_ptr_count), 1);
    }

    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(run_count), 1);
    0
}

bpf_object!("GPL");
