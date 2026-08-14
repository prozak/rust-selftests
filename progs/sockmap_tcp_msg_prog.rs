#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/sockmap_tcp_msg_prog.c (bpf-rs-core
// idiom). The ctx is never dereferenced, so it stays opaque.

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

const SK_PASS: i32 = 1;

#[link_section = "sk_msg1"]
#[no_mangle]
extern "C" fn bpf_prog1(_msg: *const c_void) -> i32 {
    SK_PASS
}

bpf_object!("GPL");
