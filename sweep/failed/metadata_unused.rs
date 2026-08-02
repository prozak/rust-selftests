#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/metadata_unused.c
// (bpf-rs-core idiom). .rodata metadata values that are never read by the
// program itself, only inspected by userspace through the skeleton.

use bpf_rs_core::bpf_object;

#[link_section = ".rodata"]
#[no_mangle]
static bpf_metadata_a: [i8; 4] = [b'f' as i8, b'o' as i8, b'o' as i8, 0];

#[link_section = ".rodata"]
#[no_mangle]
static bpf_metadata_b: i32 = 1;

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn prog(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

bpf_object!("GPL");
