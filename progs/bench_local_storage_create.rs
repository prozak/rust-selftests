// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/bench_local_storage_create.c
// (bpf-rs-core idiom). benchs/bench_local_storage_create.c sets
// `bench_pid`, attaches one of the two programs and forks or creates
// sockets: the sched_process_fork tracepoint creates a task-storage
// element for every child of the benchmark, the sleepable LSM hook a
// socket-storage element for every socket it creates, counting
// `create_cnts`/`create_errs`. `parent->tgid` and `sock->sk` are direct
// reads of trusted tracing arguments through `#[btf]` views. The C names
// its license global `__license` (bpftool_ringbuf.rs: the keep-list is the
// C object's symbols, so the crate's `_license` alone would be dropped).
// The .bss order is the C's (`// C_LAYOUT:`).
// C_LAYOUT: .bss

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_sk_storage_get, bpf_task_storage_get, sync_fetch_and_add,
};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

#[no_mangle]
static mut create_errs: isize = 0;
#[no_mangle]
static mut create_cnts: isize = 0;
#[no_mangle]
static mut bench_pid: u32 = 0;

#[allow(non_camel_case_types)]
#[repr(C)]
struct storage {
    data: [u8; 64],
}

bpf_map! {
    sk_storage_map {
        r#type: *const [i32; 24], // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const storage,
    }
}

bpf_map! {
    task_storage_map {
        r#type: *const [i32; 29], // BPF_MAP_TYPE_TASK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const storage,
    }
}

#[btf]
struct task_struct {
    tgid: i32,
}

#[btf]
struct sock {
    _priv: [u8; 0],
}

#[btf]
struct socket {
    sk: *mut sock,
}

#[link_section = "tp_btf/sched_process_fork"]
#[no_mangle]
extern "C" fn sched_process_fork(ctx: *const u64) -> i32 {
    let parent = arg(ctx, 0) as *const task_struct;
    let child = arg(ctx, 1) as *mut task_struct;

    if unsafe { *(&*parent).tgid().as_ptr() } as u32 != unsafe { bench_pid } {
        return 0;
    }

    let stg = bpf_task_storage_get(
        &task_storage_map,
        child,
        core::ptr::null(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    );
    if !stg.is_null() {
        sync_fetch_and_add(unsafe { addr_of_mut!(create_cnts) }, 1);
    } else {
        sync_fetch_and_add(unsafe { addr_of_mut!(create_errs) }, 1);
    }
    0
}

#[link_section = "lsm.s/socket_post_create"]
#[no_mangle]
extern "C" fn socket_post_create(ctx: *const u64) -> i32 {
    let sockp = arg(ctx, 0) as *const socket;
    let sk = unsafe { *(&*sockp).sk().as_ptr() };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { bench_pid } || sk.is_null() {
        return 0;
    }

    let stg = bpf_sk_storage_get(
        &sk_storage_map,
        sk as *mut c_void,
        core::ptr::null(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    );
    if !stg.is_null() {
        sync_fetch_and_add(unsafe { addr_of_mut!(create_cnts) }, 1);
    } else {
        sync_fetch_and_add(unsafe { addr_of_mut!(create_errs) }, 1);
    }
    0
}

#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
