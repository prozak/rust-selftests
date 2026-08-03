#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/atomic_bounds.c
// (bpf-rs-core idiom).
//
// This target's reference object is built with -DENABLE_ATOMICS_TESTS (same
// environment as atomics.rs, see [[arena-programs-blocked-by-addrspace-and-kfunc-proto]]
// history), so skip_tests is false and the atomic op below is live, not the
// C source's `#else bool skip_tests = true;` fallback.

use bpf_rs_core::bpf_object;
use core::sync::atomic::{AtomicI32, Ordering};

#[link_section = ".data"]
#[no_mangle]
static mut skip_tests: bool = false;

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn sub(_ctx: *const u64) -> i32 {
    let mut a: i32 = 0;
    let b = unsafe {
        (*(core::ptr::addr_of_mut!(a) as *mut AtomicI32)).fetch_add(1, Ordering::SeqCst)
    };
    // b is certainly 0 here. Can the verifier tell?
    while b != 0 {}
    0
}

bpf_object!("GPL");
