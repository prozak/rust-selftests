#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall3.c,
// bpf-rs-core idiom.
//
// jmp_table has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch rather than the BpfMap<K,V,TYPE,MAX>
// generic (matches tailcall4.rs idiom). bpf_tail_call_static's constant-slot
// asm is a JIT-poke optimization, not behavioral; the regular bpf_tail_call
// thunk with a literal index is functionally equivalent for this test.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 2],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[no_mangle]
static mut count: i32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(skb: *const __sk_buff) -> i32 {
    unsafe { count += 1 };
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 0);
    1
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry(skb: *const __sk_buff) -> i32 {
    // prog == NULL case
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 1);

    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 0);
    0
}

bpf_object!("GPL");
