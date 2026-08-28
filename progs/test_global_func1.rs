#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func1.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: three noinline global functions with 260-byte
// stack buffers overflow the 512-byte combined stack limit, and
// __failure/__msg("combined stack size of 3 calls is") encode that
// expectation as BTF decl tags the RUN_TESTS test_loader reads from the
// object itself.
//
// rustc emits no BTF_KIND_DECL_TAG (clang derives it from
// __attribute__((btf_decl_tag)) via DI annotations rustc cannot produce), so
// the expectation is declared below with test_tags! and appended to the built
// object's .BTF by scripts/btf_test_tags.py.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{sink, sink_val};
use bpf_rs_core::test_tags;

// C: #define MAX_STACK 260 -- three of these on one call chain is what
// blows the 512-byte combined stack limit the test asserts.
const MAX_STACK: usize = 260;

// C: volatile char buf[MAX_STACK] = {}; __sink(buf[MAX_STACK - 1]);
// sink() makes the array address escape, so the whole buffer stays on the
// stack (SROA/DSE cannot split or drop an alloca with escaping uses).
#[inline(always)]
fn stack_buf() {
    let mut buf = [0u8; MAX_STACK];
    let mut p = buf.as_mut_ptr();
    sink(&mut p);
    unsafe {
        core::ptr::read_volatile(p.add(MAX_STACK - 1));
    }
}

// static in C; #[no_mangle] keeps the name and full signature through
// rustc (no dead-arg-elim), and the build's internalize pass demotes it
// back to a local/static symbol since it is not in the C object keep-list.
#[no_mangle]
#[inline(never)]
extern "C" fn f0(var: i32, skb: *const __sk_buff) -> i32 {
    // C: asm volatile (""); consuming `var` also keeps dead-arg-elim from
    // dropping it, preserving the C signature in BTF.
    sink_val(var);
    unsafe { (*skb).len as i32 }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f1(skb: *const __sk_buff) -> i32 {
    stack_buf();
    f0(0, skb).wrapping_add(unsafe { (*skb).len as i32 })
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f2(val: i32, skb: *const __sk_buff) -> i32 {
    stack_buf();
    f1(skb).wrapping_add(f3(val, skb, 1))
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f3(val: i32, skb: *const __sk_buff, var: i32) -> i32 {
    stack_buf();
    (unsafe { (*skb).ifindex } as i32).wrapping_mul(val).wrapping_mul(var)
}

test_tags! {
    global_func1: __failure, __msg("combined stack size of 3 calls is");
}

#[link_section = "tc"]
#[no_mangle]
pub extern "C" fn global_func1(skb: *const __sk_buff) -> i32 {
    f0(1, skb)
        .wrapping_add(f1(skb))
        .wrapping_add(f2(2, skb))
        .wrapping_add(f3(3, skb, 4))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
