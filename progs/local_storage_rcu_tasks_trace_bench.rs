// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/local_storage_rcu_tasks_trace_bench.c
// (bpf-rs-core idiom). benchs/bench_local_storage_rcu_tasks_trace.c
// attaches the three programs and reads `hits`, `gp_hits`, `gp_times` and
// `unexpected`: each getpgid() creates and deletes a task-storage element
// (the delete needs an RCU tasks trace grace period), and the two fentry
// programs on the grace-period steps time each period. `postgp_seen` is
// the C's `bool` global, declared u8 (translint bool-global) and tested
// as clang tests it (`w &= 1; if w == 0`: the low bit).

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_task_storage_delete, bpf_task_storage_get,
    sync_fetch_and_add,
};
use bpf_rs_core::{bpf_map, bpf_object};

const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

bpf_map! {
    task_storage {
        r#type: *const [i32; 29], // BPF_MAP_TYPE_TASK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i32,
    }
}

#[no_mangle]
static mut hits: isize = 0;
#[no_mangle]
static mut gp_hits: isize = 0;
#[no_mangle]
static mut gp_times: isize = 0;
#[no_mangle]
static mut current_gp_start: isize = 0;
#[no_mangle]
static mut unexpected: isize = 0;
#[no_mangle]
static mut postgp_seen: u8 = 0;

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn get_local(_ctx: *mut c_void) -> i32 {
    let idx: i32 = 0;

    let task: *mut c_void = bpf_get_current_task_btf();
    let s = bpf_task_storage_get(
        &task_storage,
        task,
        &idx as *const i32 as *const c_void,
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut i32;
    if s.is_null() {
        return 0;
    }

    unsafe { *s = 3 };
    bpf_task_storage_delete(&task_storage, task);
    sync_fetch_and_add(unsafe { addr_of_mut!(hits) }, 1);
    0
}

#[link_section = "fentry/rcu_tasks_trace_pregp_step"]
#[no_mangle]
extern "C" fn pregp_step(_ctx: *mut c_void) -> i32 {
    unsafe { current_gp_start = bpf_ktime_get_ns() as isize };
    0
}

#[link_section = "fentry/rcu_tasks_trace_postgp"]
#[no_mangle]
extern "C" fn postgp(_ctx: *mut c_void) -> i32 {
    unsafe {
        if current_gp_start == 0 && postgp_seen & 1 != 0 {
            /* Will only happen if prog tracing rcu_tasks_trace_pregp_step doesn't
             * execute before this prog
             */
            sync_fetch_and_add(addr_of_mut!(unexpected), 1);
            return 0;
        }

        sync_fetch_and_add(
            addr_of_mut!(gp_times),
            (bpf_ktime_get_ns() as isize).wrapping_sub(current_gp_start),
        );
        sync_fetch_and_add(addr_of_mut!(gp_hits), 1);
        current_gp_start = 0;
        postgp_seen = 1;
    }
    0
}

bpf_object!("GPL");
