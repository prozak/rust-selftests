#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func2.c,
// bpf-rs-core idiom.
//
// __success verifier test: four global noinline functions (f0..f3) with
// MAX_STACK = 512 - 3*32 = 416-byte volatile stack buffers in f1/f3. The
// call graph and buffer sizes are kept identical to the C original so the
// combined-stack accounting the verifier performs matches exactly.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{sink, sink_val};

const MAX_STACK: usize = 512 - 3 * 32;

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
    f1(skb).wrapping_add(f3(val, skb, 1))
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f3(val: i32, skb: *const __sk_buff, var: i32) -> i32 {
    stack_buf();
    (unsafe { (*skb).ifindex } as i32)
        .wrapping_mul(val)
        .wrapping_mul(var)
}

#[link_section = "tc"]
#[no_mangle]
pub extern "C" fn global_func2(skb: *const __sk_buff) -> i32 {
    f0(1, skb)
        .wrapping_add(f1(skb))
        .wrapping_add(f2(2, skb))
        .wrapping_add(f3(3, skb, 4))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
