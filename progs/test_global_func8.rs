#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func8.c,
// bpf-rs-core idiom. __success verifier test: a noinline global function
// call whose result gates a branch.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_get_prandom_u32;

#[no_mangle]
#[inline(never)]
pub extern "C" fn foo(_skb: *const __sk_buff) -> i32 {
    bpf_get_prandom_u32() as i32
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
pub extern "C" fn global_func8(skb: *const __sk_buff) -> i32 {
    if foo(skb) == 0 {
        return 0;
    }

    1
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
