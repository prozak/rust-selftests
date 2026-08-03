#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_bpf_rhash_map.c
// (bpf-rs-core idiom).

use bpf_rs_core::{bpf_map, bpf_object};
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__bpf_map_elem {
    meta: *mut bpf_iter_meta,
    map: *mut c_void,
    key: *mut c_void,
    value: *mut c_void,
}

bpf_map! {
    rhashmap {
        r#type: *const [i32; 35],       // BPF_MAP_TYPE_RHASH
        map_flags: *const [i32; 1],     // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 64],
        key: *const u32,
        value: *const u64,
    }
}

#[no_mangle]
static mut key_sum: u32 = 0;
#[no_mangle]
static mut val_sum: u64 = 0;
#[no_mangle]
static mut elem_count: u32 = 0;
#[no_mangle]
static mut err: u32 = 0;

#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
extern "C" fn dump_bpf_rhash_map(ctx: *const bpf_iter__bpf_map_elem) -> i32 {
    let ctx = unsafe { &*ctx };
    let key = ctx.key as *const u32;
    let val = ctx.value as *const u64;

    if key.is_null() || val.is_null() {
        return 0;
    }

    unsafe {
        key_sum += *key;
        val_sum += *val;
        elem_count += 1;
    }
    0
}

bpf_object!("GPL");
