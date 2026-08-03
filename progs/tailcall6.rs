#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall6.c,
// bpf-rs-core idiom.
//
// prog_array has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch rather than the BpfMap<K,V,TYPE,MAX>
// generic (same pattern as tailcall_cgrp_storage_no_storage.rs).
//
// The C source's `__builtin_constant_p(which)` guard is a clang-specific
// dead-code hint (which is never a compile-time constant, so the guard
// never fires at runtime); it has no rustc equivalent and is simply
// omitted here.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[no_mangle]
static mut count: i32 = 0;

#[no_mangle]
static mut which: i32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(skb: *const __sk_buff) -> i32 {
    unsafe {
        count += 1;
    }
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, unsafe { which } as u32);
    1
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry(skb: *const __sk_buff) -> i32 {
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, unsafe { which } as u32);
    0
}

bpf_object!("GPL");
