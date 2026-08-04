#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall_bpf2bpf2.c,
// bpf-rs-core idiom.
//
// jmp_table has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch (same pattern as tailcall6.rs).
//
// C's `load_byte(skb, 0)` is the llvm.bpf.load.byte LD_ABS builtin; there is
// no Rust equivalent available here, so it is replaced with the functionally
// equivalent bpf_skb_load_bytes() helper read of the same offset/length —
// every consuming test in prog_tests/tailcalls.c runs with a zeroed 128-byte
// packet, so both always take the `== 0` branch.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{barrier_var, bpf_skb_load_bytes, bpf_tail_call};
use bpf_rs_core::{bpf_map, bpf_object, maps};
use core::ffi::c_void;

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[inline(never)]
extern "C" fn subprog_tail(skb: *const __sk_buff) -> i32 {
    let mut ret: usize = 1;
    let mut byte: u8 = 0;
    unsafe {
        bpf_skb_load_bytes(
            skb as *const c_void,
            0,
            &mut byte as *mut u8 as *mut c_void,
            1,
        );
    }
    if byte != 0 {
        bpf_tail_call(skb as *const c_void, &jmp_table, 1);
    } else {
        bpf_tail_call(skb as *const c_void, &jmp_table, 0);
    }
    barrier_var(&mut ret);
    ret as i32
}

#[no_mangle]
static mut count: i32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(skb: *const __sk_buff) -> i32 {
    unsafe {
        count += 1;
    }
    subprog_tail(skb)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry(skb: *const __sk_buff) -> i32 {
    bpf_tail_call(skb as *const c_void, &jmp_table, 0);
    0
}

bpf_object!("GPL");
