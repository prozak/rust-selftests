#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_sockmap.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_delete_elem, bpf_map_update_elem_ptr};
use bpf_rs_core::maps::BpfMap;
use core::ffi::c_void;

/// enum bpf_map_type::BPF_MAP_TYPE_SOCKMAP / BPF_MAP_TYPE_SOCKHASH
/// (not in bpf-rs-core::maps yet).
const SOCKMAP: usize = 15;
const SOCKHASH: usize = 18;

const ENOENT: i64 = 2;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__sockmap {
    meta: *mut bpf_iter_meta,
    map: *mut c_void,
    key: *mut u32,
    sk: *mut c_void,
}

#[link_section = ".maps"]
#[no_mangle]
static sockmap: BpfMap<u32, u64, SOCKMAP, 64> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static sockhash: BpfMap<u32, u64, SOCKHASH, 64> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static dst: BpfMap<u32, u64, SOCKHASH, 64> = BpfMap::new();

#[no_mangle]
static mut elems: u32 = 0;
#[no_mangle]
static mut socks: u32 = 0;

#[link_section = "iter/sockmap"]
#[no_mangle]
extern "C" fn copy(ctx: *const bpf_iter__sockmap) -> i32 {
    let ctx = unsafe { &*ctx };

    let sk = ctx.sk;
    let key = ctx.key;

    if key.is_null() {
        return 0;
    }

    unsafe {
        elems += 1;
    }

    // We need a temporary buffer on the stack, since the verifier doesn't
    // let us use the pointer from the context as an argument to the helper.
    let tmp: u32 = unsafe { *key };

    if !sk.is_null() {
        unsafe {
            socks += 1;
        }
        return (bpf_map_update_elem_ptr(&dst, &tmp, sk, 0) != 0) as i32;
    }

    let ret = bpf_map_delete_elem(&dst, &tmp);
    (ret != 0 && ret != -ENOENT) as i32
}

bpf_object!("GPL");
