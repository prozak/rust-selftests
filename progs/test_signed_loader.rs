#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_signed_loader.c
// bpf-rs-core idiom.
//
// Minimal, map-less program driven through libbpf's gen_loader by
// prog_tests/signed_loader.c to exercise the signed-metadata load path.

use bpf_rs_core::bpf_object;

#[link_section = "socket"]
#[no_mangle]
extern "C" fn probe(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

bpf_object!("GPL");
