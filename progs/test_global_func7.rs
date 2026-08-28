#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func7.c,
// bpf-rs-core idiom.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::vstore;
use bpf_rs_core::test_tags;

#[no_mangle]
#[inline(never)]
extern "C" fn foo(skb: *mut __sk_buff) {
    vstore!((*skb).tc_index, 0);
}

test_tags! {
    global_func7: __success;
}

#[link_section = "tc"]
#[no_mangle]
pub extern "C" fn global_func7(skb: *mut __sk_buff) -> i32 {
    foo(skb);
    0
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
