#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall_bpf2bpf6.c
// (bpf-rs-core idiom).
//
// jmp_table has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch rather than the BpfMap<K,V,TYPE,MAX>
// generic (same shape as tailcall_bpf2bpf1.rs / tailcall_poke.rs).
//
// `subprog_tail`'s C body keeps a `volatile int ret` so the constant 1
// doesn't propagate to the caller across the tail call; `entry`'s C body
// keeps a `volatile char arr[1]` (a stack slot whose size is not a
// multiple of 8) alive via `__sink()` before the bpf2bpf call into
// subprog_tail. Reproduced with read/write_volatile plus helpers::sink
// (self-move on the pointer) so LLVM can't fold the value away or SROA
// the stack slot out of existence.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{self, bpf_tail_call};
use bpf_rs_core::maps;
use core::ffi::c_void;

#[no_mangle]
static mut done: i32 = 0;

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(_skb: *const __sk_buff) -> i32 {
    unsafe {
        done = 1;
    }
    0
}

#[no_mangle]
#[inline(never)]
extern "C" fn subprog_tail(skb: *const __sk_buff) -> i32 {
    let mut ret: i32 = 1;
    unsafe {
        core::ptr::write_volatile(&mut ret, 1);
    }

    bpf_tail_call(skb as *const c_void, &jmp_table, 0);

    unsafe { core::ptr::read_volatile(&ret) }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry(skb: *const __sk_buff) -> i32 {
    let mut arr: [u8; 1] = [0; 1];
    let mut p = arr.as_mut_ptr();
    unsafe {
        core::ptr::write_volatile(p, 0);
    }
    helpers::sink(&mut p);

    subprog_tail(skb)
}

bpf_object!("GPL");
