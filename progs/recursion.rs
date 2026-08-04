#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/recursion.c
// bpf-rs-core idiom.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_delete_elem;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;

#[link_section = ".maps"]
#[no_mangle]
static hash1: BpfMap<i32, i64, { maps::HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static hash2: BpfMap<i32, i64, { maps::HASH }, 1> = BpfMap::new();

#[no_mangle]
static mut pass1: i32 = 0;
#[no_mangle]
static mut pass2: i32 = 0;

#[link_section = "fentry/htab_map_delete_elem"]
#[no_mangle]
extern "C" fn on_delete(ctx: *const u64) -> i32 {
    let map = arg(ctx, 0) as *const c_void;
    let key: i32 = 0;

    if map == core::ptr::addr_of!(hash1) as *const c_void {
        unsafe { pass1 += 1 };
        return 0;
    }
    if map == core::ptr::addr_of!(hash2) as *const c_void {
        unsafe { pass2 += 1 };
        bpf_map_delete_elem(&hash2, &key);
        return 0;
    }

    0
}

bpf_object!("GPL");
