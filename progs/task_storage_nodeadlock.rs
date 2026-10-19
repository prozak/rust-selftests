// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/task_storage_nodeadlock.c (bpf-rs-core
// idiom). prog_tests/task_local_storage.c (test_nodeadlock) attaches the
// sleepable LSM program, hammers socket creation from several threads and
// expects both error counters to stay zero; it skips unless
// `skel->kconfig->CONFIG_PREEMPTION`, the C's weak `__kconfig` bool
// (`// BTF_KCONFIG:` below, scripts/ksym_vars.py mirrors the C object's
// declaration). clang compiles `if (!CONFIG_PREEMPTION)` as `w != 1`, so
// the Rust compares `!= 1` (TRANSLATING.md "kconfig externs").

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_task_storage_delete, bpf_task_storage_get,
    sync_fetch_and_add_i32,
};
use core::ffi::c_void;
use core::ptr::addr_of_mut;

const EDEADLK: i32 = 35;
const ETIMEDOUT: i32 = 110;
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

// BTF_KCONFIG: CONFIG_PREEMPTION
extern "C" {
    static CONFIG_PREEMPTION: u8;
}
#[no_mangle]
static mut nr_get_errs: i32 = 0;
#[no_mangle]
static mut nr_del_errs: i32 = 0;

bpf_map! {
    task_storage {
        r#type: *const [i32; 29],   // BPF_MAP_TYPE_TASK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i32,
    }
}

#[link_section = "lsm.s/socket_post_create"]
#[no_mangle]
extern "C" fn socket_post_create(_ctx: *const u64) -> i32 {
    let zero: i32 = 0;

    if unsafe { CONFIG_PREEMPTION } != 1 {
        return 0;
    }

    let task = bpf_get_current_task_btf::<c_void>();
    let value = bpf_task_storage_get(
        &task_storage,
        task,
        &zero as *const i32 as *const c_void,
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    );
    if value.is_null() {
        sync_fetch_and_add_i32(addr_of_mut!(nr_get_errs), 1);
    }

    let ret = bpf_task_storage_delete(&task_storage, bpf_get_current_task_btf::<c_void>()) as i32;
    if ret == -EDEADLK || ret == -ETIMEDOUT {
        sync_fetch_and_add_i32(addr_of_mut!(nr_del_errs), 1);
    }

    0
}

bpf_object!("GPL");
