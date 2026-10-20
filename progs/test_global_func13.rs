// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func13.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test: a scalar constant (0xbedabeda) is passed where
// the global function declares a `struct S *` parameter; the verifier
// rejects the caller's argument type.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_get_prandom_u32;
use bpf_rs_core::test_tags;

#[repr(C)]
struct S {
    x: i32,
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn foo(s: *const S) -> i32 {
    // C: if (s) return bpf_get_prandom_u32() < s->x; return 0;
    if !s.is_null() {
        return (bpf_get_prandom_u32() < unsafe { (*s).x } as u32) as i32;
    }
    0
}

test_tags! {
    global_func13: __failure, __msg("Caller passes invalid args into func#1");
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
pub extern "C" fn global_func13(_skb: *const __sk_buff) -> i32 {
    // C: const struct S *s = (const struct S *)(0xbedabeda);
    foo(0xbedabedau32 as usize as *const S)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
