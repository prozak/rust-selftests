#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_bpf_sk_storage_helpers.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_sk_storage_delete, bpf_sk_storage_get, bpf_sock_from_file};
use btf_macros::btf;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__bpf_sk_storage_map {
    meta: *mut bpf_iter_meta,
    map: *mut c_void,
    sk: *mut c_void,
    value: *mut c_void,
}

#[repr(C)]
struct bpf_iter__task_file {
    meta: *mut bpf_iter_meta,
    task: *mut task_struct,
    fd: u32,
    file: *mut c_void,
}

#[repr(C)]
struct bpf_iter__tcp {
    meta: *mut bpf_iter_meta,
    sk_common: *mut c_void,
}

#[btf]
struct task_struct {
    tgid: i32,
}

#[btf]
struct socket {
    sk: *const u8,
}

bpf_map! {
    sk_stg_map {
        r#type: *const [i32; 24],  // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i32,
    }
}

#[link_section = "iter/bpf_sk_storage_map"]
#[no_mangle]
extern "C" fn delete_bpf_sk_storage_map(ctx: *const bpf_iter__bpf_sk_storage_map) -> i32 {
    let ctx = unsafe { &*ctx };

    if !ctx.sk.is_null() {
        bpf_sk_storage_delete(&sk_stg_map, ctx.sk);
    }

    0
}

#[link_section = "iter/task_file"]
#[no_mangle]
extern "C" fn fill_socket_owner(ctx: *const bpf_iter__task_file) -> i32 {
    let ctx = unsafe { &*ctx };
    let task = ctx.task;
    let file = ctx.file;

    if task.is_null() || file.is_null() {
        return 0;
    }

    let sock = bpf_sock_from_file(file) as *mut socket;
    if sock.is_null() {
        return 0;
    }

    let sk = unsafe { *(&*sock).sk().as_ptr() } as *mut c_void;
    let sock_tgid = bpf_sk_storage_get(&sk_stg_map, sk, core::ptr::null_mut(), 0) as *mut i32;
    if sock_tgid.is_null() {
        return 0;
    }

    let task_ref = unsafe { &*task };
    let task_tgid = unsafe { *task_ref.tgid().as_ptr() };
    unsafe { *sock_tgid = task_tgid };

    0
}

#[link_section = "iter/tcp"]
#[no_mangle]
extern "C" fn negate_socket_local_storage(ctx: *const bpf_iter__tcp) -> i32 {
    let ctx = unsafe { &*ctx };
    let sk_common = ctx.sk_common;

    if sk_common.is_null() {
        return 0;
    }

    let sock_tgid = bpf_sk_storage_get(&sk_stg_map, sk_common, core::ptr::null_mut(), 0) as *mut i32;
    if sock_tgid.is_null() {
        return 0;
    }

    unsafe { *sock_tgid = -*sock_tgid };

    0
}

bpf_object!("GPL");
