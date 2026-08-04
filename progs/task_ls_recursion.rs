#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/task_ls_recursion.c,
// bpf-rs-core idiom.

use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_task_storage_delete, bpf_task_storage_get,
};
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

const BPF_MAP_TYPE_TASK_STORAGE: i32 = 29;
const BPF_F_NO_PREALLOC: i32 = 1;
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;
const EBUSY: i64 = 16;

bpf_map! {
    map_a {
        r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
        map_flags: *const [i32; BPF_F_NO_PREALLOC as usize],
        key: *const i32,
        value: *const isize,
    }
}

bpf_map! {
    map_b {
        r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
        map_flags: *const [i32; BPF_F_NO_PREALLOC as usize],
        key: *const i32,
        value: *const isize,
    }
}

#[no_mangle]
static mut nr_del_errs: i32 = 0;
#[no_mangle]
static mut test_pid: i32 = 0;

#[link_section = "fentry/bpf_local_storage_update"]
#[no_mangle]
extern "C" fn on_update(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();

    let tp = unsafe { test_pid };
    if tp == 0 || *unsafe { &*task }.pid().get().unwrap() != tp {
        return 0;
    }

    // This will succeed as there is no real deadlock
    let ptr = bpf_task_storage_get(
        &map_a,
        task,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut isize;
    if !ptr.is_null() {
        unsafe { *ptr += 1 };
        let err = bpf_task_storage_delete(&map_a, task);
        if err == -EBUSY {
            unsafe { nr_del_errs += 1 };
        }
    }

    // This will succeed as there is no real deadlock
    let ptr = bpf_task_storage_get(
        &map_b,
        task,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut isize;
    if !ptr.is_null() {
        unsafe { *ptr += 1 };
    }

    0
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn on_enter(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();

    let tp = unsafe { test_pid };
    if tp == 0 || *unsafe { &*task }.pid().get().unwrap() != tp {
        return 0;
    }

    let ptr = bpf_task_storage_get(
        &map_a,
        task,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut isize;
    if !ptr.is_null() && unsafe { *ptr } == 0 {
        unsafe { *ptr = 200 };
    }

    let ptr = bpf_task_storage_get(
        &map_b,
        task,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut isize;
    if !ptr.is_null() && unsafe { *ptr } == 0 {
        unsafe { *ptr = 100 };
    }

    0
}

bpf_object!("GPL");
