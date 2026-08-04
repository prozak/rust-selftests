#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall_bpf2bpf4.c,
// bpf-rs-core idiom.
//
// nop_table/jmp_table both use explicit key_size/value_size (not
// __type(key,...)/__type(value,...)), so they need the bpf_map! escape
// hatch (same pattern as tailcall_bpf2bpf2.rs / tailcall6.rs).
//
// subprog_tail/_1/_2 are `__noinline` WITHOUT `static` in the C source, so
// they have external linkage and are part of the C object's global
// FUNC keep-list; translated as #[no_mangle] extern "C" fn with no
// #[link_section] (same pattern as test_global_func1.rs's f1/f2/f3).
// subprog_noise is `static __always_inline`, translated as a private
// #[inline(always)] fn.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_tail_call};
use bpf_rs_core::{bpf_map, bpf_object, maps};
use core::ffi::c_void;

bpf_map! {
    nop_table {
        r#type: *const [i32; maps::ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 3],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[no_mangle]
static mut count: i32 = 0;

#[no_mangle]
static mut noise: i32 = 0;

#[inline(always)]
fn subprog_noise() -> i32 {
    let key: u32 = 0;
    bpf_map_lookup_elem(&nop_table, &key);
    0
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn subprog_tail_2(skb: *const __sk_buff) -> i32 {
    if unsafe { noise } != 0 {
        subprog_noise();
    }
    bpf_tail_call(skb as *const c_void, &jmp_table, 2);
    unsafe { (*skb).len as i32 * 3 }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn subprog_tail_1(skb: *const __sk_buff) -> i32 {
    bpf_tail_call(skb as *const c_void, &jmp_table, 1);
    unsafe { (*skb).len as i32 * 2 }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn subprog_tail(skb: *const __sk_buff) -> i32 {
    bpf_tail_call(skb as *const c_void, &jmp_table, 0);
    unsafe { (*skb).len as i32 }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_1(skb: *const __sk_buff) -> i32 {
    subprog_tail_2(skb)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_2(skb: *const __sk_buff) -> i32 {
    unsafe {
        count += 1;
    }
    subprog_tail_2(skb)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(skb: *const __sk_buff) -> i32 {
    subprog_tail_1(skb)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry(skb: *const __sk_buff) -> i32 {
    subprog_tail(skb)
}

bpf_object!("GPL");
