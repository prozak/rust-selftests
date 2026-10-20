// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func17.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: the address of a read-only global (`const
// volatile int i`, a .rodata map value) is passed to a global function whose
// parameter is `int *p`, which the verifier types as a pointer to writable
// memory. The caller's argument type does not match, so the load is
// rejected with the message declared below (the C object's decl tag,
// appended to the Rust object by scripts/btf_test_tags.py).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::test_tags;
use core::hint::black_box;

#[no_mangle]
#[inline(never)]
pub extern "C" fn foo(p: *mut i32) -> i32 {
    // C: barrier_var(p); return p ? (*p = 42) : 0;
    let p = black_box(p);
    if !p.is_null() {
        unsafe { *p = 42 };
        42
    } else {
        0
    }
}

// C: const volatile int i;
#[allow(non_upper_case_globals)]
#[link_section = ".rodata"]
#[no_mangle]
static i: i32 = 0;

test_tags! {
    global_func17: __failure, __msg("Caller passes invalid args into func#1");
}

#[link_section = "tc"]
#[no_mangle]
pub extern "C" fn global_func17(_skb: *const __sk_buff) -> i32 {
    foo(core::ptr::addr_of!(i) as *mut i32)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
