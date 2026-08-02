#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/security_bpf_map.c
// bpf-rs-core idiom.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;

const FMODE_WRITE: i32 = 0x2;
const EPERM: i32 = 1;
const BPF_ANY: u64 = 0;

#[link_section = ".maps"]
#[no_mangle]
static prot_status_map: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static prot_map: BpfMap<u32, u32, { maps::HASH }, 3> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static not_prot_map: BpfMap<u32, u32, { maps::HASH }, 3> = BpfMap::new();

#[link_section = "fmod_ret/security_bpf_map"]
#[no_mangle]
extern "C" fn fmod_bpf_map(ctx: *const u64) -> i32 {
    let map = arg(ctx, 0) as *const c_void;
    let fmode = arg(ctx, 1) as i32;

    let key: u32 = 0;
    let status_ptr = bpf_map_lookup_elem(&prot_status_map, &key) as *const u32;
    if status_ptr.is_null() || unsafe { *status_ptr } == 0 {
        return 0;
    }

    if map == core::ptr::addr_of!(prot_map) as *const c_void {
        if fmode & FMODE_WRITE != 0 {
            return -EPERM;
        }
    }

    0
}

/*
 * This program keeps references to maps. This is needed to prevent
 * optimizing them out.
 */
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fentry_dummy1(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32;
    let key: u32 = 0;
    let val1: u32 = a as u32;
    let val2: u32 = (a + 1) as u32;

    bpf_map_update_elem(&prot_map, &key, &val1, BPF_ANY);
    bpf_map_update_elem(&not_prot_map, &key, &val2, BPF_ANY);
    0
}

bpf_object!("GPL");
