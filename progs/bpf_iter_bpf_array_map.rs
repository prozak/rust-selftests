#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_bpf_array_map.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_map_update_elem, bpf_seq_write};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const BPF_ANY: u64 = 0;

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
static arraymap1: BpfMap<u32, u64, { maps::ARRAY }, 3> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static hashmap1: BpfMap<u64, u32, { maps::HASH }, 10> = BpfMap::new();

#[no_mangle]
static mut key_sum: u32 = 0;
#[no_mangle]
static mut val_sum: u64 = 0;

#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
extern "C" fn dump_bpf_array_map(ctx: *const bpf_iter__bpf_map_elem) -> i32 {
    let ctx = unsafe { &*ctx };
    let key = ctx.key as *mut u32;
    let val = ctx.value as *mut u64;

    if key.is_null() || val.is_null() {
        return 0;
    }

    let meta = unsafe { &*ctx.meta };
    let key_val = unsafe { *key };
    let val_val = unsafe { *val };

    bpf_seq_write(meta.seq, key as *const c_void, core::mem::size_of::<u32>() as u32);
    bpf_seq_write(meta.seq, val as *const c_void, core::mem::size_of::<u64>() as u32);
    unsafe { key_sum += key_val };
    unsafe { val_sum += val_val };

    // workaround - It's necessary to do this convoluted (val, key)
    // write into hashmap1, instead of simply doing
    //   bpf_map_update_elem(&hashmap1, val, key, BPF_ANY);
    // because key has MEM_RDONLY flag and bpf_map_update elem expects
    // types without this flag
    bpf_map_update_elem(&hashmap1, unsafe { &*val }, unsafe { &*val }, BPF_ANY);
    let hmap_val = bpf_map_lookup_elem(&hashmap1, unsafe { &*val }) as *mut u32;
    if !hmap_val.is_null() {
        unsafe { *hmap_val = key_val };
    }

    unsafe { *val = key_val as u64 };
    0
}

bpf_object!("GPL");
