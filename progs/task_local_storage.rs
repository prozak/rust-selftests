#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/task_local_storage.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_task_storage_get, sync_fetch_and_add_i32,
};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

bpf_map! {
    enter_id {
        r#type: *const [i32; 29],   // BPF_MAP_TYPE_TASK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i64,          // long
    }
}

#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut mismatch_cnt: i32 = 0;
#[no_mangle]
static mut enter_cnt: i32 = 0;
#[no_mangle]
static mut exit_cnt: i32 = 0;
#[no_mangle]
static mut update_err: isize = 0;

const MAGIC_VALUE: i64 = 0xabcd1234;
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;
const MAX_ERRNO: u64 = 4095;

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn on_enter(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let pid = *unsafe { &*task }.pid().get().unwrap();
    if pid != unsafe { target_pid } {
        return 0;
    }

    let ptr = bpf_task_storage_get(
        &enter_id,
        task,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut i64;
    if ptr.is_null() {
        return 0;
    }

    sync_fetch_and_add_i32(core::ptr::addr_of_mut!(enter_cnt), 1);
    unsafe { *ptr = MAGIC_VALUE + enter_cnt as i64 };

    0
}

#[link_section = "tp_btf/sys_exit"]
#[no_mangle]
extern "C" fn on_exit(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let pid = *unsafe { &*task }.pid().get().unwrap();
    if pid != unsafe { target_pid } {
        return 0;
    }

    let ptr = bpf_task_storage_get(
        &enter_id,
        task,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut i64;
    if ptr.is_null() {
        return 0;
    }

    sync_fetch_and_add_i32(core::ptr::addr_of_mut!(exit_cnt), 1);
    if unsafe { *ptr } != MAGIC_VALUE + unsafe { exit_cnt } as i64 {
        sync_fetch_and_add_i32(core::ptr::addr_of_mut!(mismatch_cnt), 1);
    }

    0
}

#[link_section = "fexit/bpf_local_storage_update"]
#[no_mangle]
extern "C" fn fexit_update(ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let pid = *unsafe { &*task }.pid().get().unwrap();
    if pid != unsafe { target_pid } {
        return 0;
    }

    let ret = arg(ctx, 5);
    if ret >= 0u64.wrapping_sub(MAX_ERRNO) {
        unsafe { update_err = ret as isize };
    }

    0
}

bpf_object!("GPL");
