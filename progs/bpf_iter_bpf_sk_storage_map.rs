#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_bpf_sk_storage_map.c
// (bpf-rs-core idiom).

use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;
use core::ffi::c_void;

// enum bpf_map_type: BPF_MAP_TYPE_SK_STORAGE.
const BPF_MAP_TYPE_SK_STORAGE: usize = 24;
// enum: BPF_F_NO_PREALLOC.
const BPF_F_NO_PREALLOC: usize = 1;

const AF_INET6: u16 = 10;

bpf_map! {
    sk_stg_map {
        r#type: *const [i32; BPF_MAP_TYPE_SK_STORAGE],
        map_flags: *const [i32; BPF_F_NO_PREALLOC],
        key: *const i32,
        value: *const i32,
    }
}

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
    sk: *mut sock,
    value: *mut u32,
}

#[btf]
struct sock_common {
    skc_family: u16,
}

#[btf]
struct sock {
    __sk_common: sock_common,
}

#[no_mangle]
static mut val_sum: u32 = 0;
#[no_mangle]
static mut ipv6_sk_count: u32 = 0;
#[no_mangle]
static mut to_add_val: u32 = 0;

#[link_section = "iter/bpf_sk_storage_map"]
#[no_mangle]
extern "C" fn rw_bpf_sk_storage_map(ctx: *const bpf_iter__bpf_sk_storage_map) -> i32 {
    let ctx = unsafe { &*ctx };
    let sk = ctx.sk;
    let val = ctx.value;

    if sk.is_null() || val.is_null() {
        return 0;
    }

    let sk_ref = unsafe { &*sk };
    let sk_family = unsafe { *sk_ref.__sk_common().skc_family().as_ptr() };
    if sk_family == AF_INET6 {
        unsafe { ipv6_sk_count += 1 };
    }

    let v = unsafe { *val };
    unsafe { val_sum += v };

    let add = unsafe { to_add_val };
    unsafe { *val = v.wrapping_add(add) };

    0
}

#[link_section = "iter/bpf_sk_storage_map"]
#[no_mangle]
extern "C" fn oob_write_bpf_sk_storage_map(ctx: *const bpf_iter__bpf_sk_storage_map) -> i32 {
    let ctx = unsafe { &*ctx };
    let sk = ctx.sk;
    let val = ctx.value;

    if sk.is_null() || val.is_null() {
        return 0;
    }

    unsafe { *val.add(1) = 0xdeadbeefu32 };

    0
}

bpf_object!("GPL");
