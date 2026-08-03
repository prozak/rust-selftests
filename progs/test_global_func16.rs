#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func16.c,
// bpf-rs-core idiom. __success verifier test: a noinline global function
// taking a pointer to a fixed-size array, guarded by a null check.

use bpf_rs_core::ctx::__sk_buff;

#[no_mangle]
#[inline(never)]
pub extern "C" fn foo(arr: *const [i32; 10]) -> i32 {
    if !arr.is_null() {
        unsafe { (*arr)[9] }
    } else {
        0
    }
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
pub extern "C" fn global_func16(_skb: *const __sk_buff) -> i32 {
    let array = [0i32; 10];

    let rv = foo(&array as *const [i32; 10]);

    if rv != 0 {
        1
    } else {
        0
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
