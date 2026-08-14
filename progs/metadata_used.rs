#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/metadata_used.c
// (bpf-rs-core idiom).
//
// The two `bpf_metadata_*` values are the point of the test: libbpf treats
// `.rodata` entries named with that prefix as object metadata, and
// prog_tests/metadata.c reads them back off the loaded object. They must
// therefore keep both their names and their section.

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[link_section = ".rodata"]
#[no_mangle]
static bpf_metadata_a: [u8; 4] = *b"bar\0";

#[link_section = ".rodata"]
#[no_mangle]
static bpf_metadata_b: i32 = 2;

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn prog(_ctx: *const c_void) -> i32 {
    // `volatile const` in C, so the read is not folded away
    if unsafe { core::ptr::read_volatile(core::ptr::addr_of!(bpf_metadata_b)) } != 0 {
        1
    } else {
        0
    }
}

bpf_object!("GPL");
