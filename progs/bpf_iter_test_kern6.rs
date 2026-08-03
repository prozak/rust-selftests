#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_test_kern6.c
// (bpf-rs-core idiom).
//
// Deliberate negative-offset out-of-bounds read: the kernel test
// (test_buf_neg_offset in prog_tests/bpf_iter.c) asserts that
// bpf_iter_test_kern6__open_and_load() FAILS, i.e. this program must be
// rejected by the verifier at load time.

use bpf_rs_core::bpf_object;
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

#[no_mangle]
static mut value_sum: u32 = 0;

#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
extern "C" fn dump_bpf_hash_map(ctx: *const bpf_iter__bpf_map_elem) -> i32 {
    let ctx = unsafe { &*ctx };
    let value = ctx.value;

    if value.is_null() {
        return 0;
    }

    // negative offset, verifier failure.
    let p = (value as *const u8).wrapping_sub(4) as *const u32;
    unsafe { value_sum += core::ptr::read_unaligned(p) };
    0
}

bpf_object!("GPL");
