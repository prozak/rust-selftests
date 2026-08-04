#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

#[repr(C)]
struct key_t {
    a: i32,
    b: i32,
    c: i32,
}

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

#[link_section = ".maps"]
#[no_mangle]
static hashmap1: BpfMap<key_t, u64, { maps::HASH }, 3> = BpfMap::new();

#[no_mangle]
static mut key_sum: u32 = 0;

#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
extern "C" fn dump_bpf_hash_map(ctx: *const bpf_iter__bpf_map_elem) -> i32 {
    let ctx = unsafe { &*ctx };
    let key = ctx.key;

    if key.is_null() {
        return 0;
    }

    /* out of bound access w.r.t. hashmap1 */
    let oob = unsafe { (key as *const u8).add(core::mem::size_of::<key_t>()) as *const u32 };
    let v = unsafe { core::ptr::read_unaligned(oob) };
    unsafe { key_sum += v };
    0
}

bpf_object!("GPL");
