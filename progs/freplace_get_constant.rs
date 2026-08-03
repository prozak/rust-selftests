#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/freplace_get_constant.c,
// bpf-rs-core idiom.
//
// freplace attach preserves the target function's own signature (get_constant
// in test_pkt_access.c: `int get_constant(long val)`) -- this is not a
// fentry/fexit trampoline with a ctx array, the replacement is called with
// the real argument directly.

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut test_get_constant: u64 = 0;

#[link_section = "freplace/get_constant"]
#[no_mangle]
extern "C" fn security_new_get_constant(val: i64) -> i32 {
    if val != 123 {
        return 0;
    }
    unsafe {
        test_get_constant = 1;
        test_get_constant as i32
    }
}

bpf_object!("GPL");
