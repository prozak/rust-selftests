#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall_bpf2bpf3.c,
// bpf-rs-core idiom.
//
// jmp_table has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch, same idiom as tailcall3.rs/tailcall4.rs.
//
// C's `subprog_tail2` reads the first word/half of the packet via the
// llvm.bpf.load.{word,half} legacy LD_ABS/LD_IND intrinsics (bpf_legacy.h);
// there's no way to emit those from stable Rust. The test only cares
// whether the condition is true or false (pkt_v4's first 4 bytes are the
// destination-MAC prefix, always zero — see network_helpers.c), so this
// reimplements the same "is the packet's first word/half word nonzero"
// check via bounds-checked direct packet access, matching the tc_chk
// pattern in test_tc_neigh_fib.rs.
//
// bpf_tail_call_static's constant-slot asm is a JIT-poke optimization, not
// behavioral; the regular bpf_tail_call thunk with a literal index is
// functionally equivalent for this test (see tailcall3.rs).
//
// Every C function declares a volatile stack array purely to consume real
// stack space (the test validates the verifier's stack-depth accounting
// across tail-call-containing subprograms); `sink()` (address-taken through
// an opaque asm barrier) reproduces that without inventing extra state.

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_tail_call, sink};
use bpf_rs_core::{bpf_map, bpf_object, maps, vload};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 2],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[no_mangle]
#[inline(never)]
extern "C" fn subprog_tail2(skb: *const __sk_buff) -> i32 {
    let mut arr = [0u8; 64];
    let mut p = arr.as_mut_ptr();

    let data = vload!((*skb).data) as usize;
    let data_end = vload!((*skb).data_end) as usize;

    let nonzero = if data + 4 <= data_end {
        let raw = data as *const u8;
        let word = unsafe { core::ptr::read_unaligned(raw as *const u32) };
        let half = unsafe { core::ptr::read_unaligned(raw as *const u16) };
        word != 0 || half != 0
    } else {
        true
    };

    if nonzero {
        bpf_tail_call(skb as *const c_void, &jmp_table, 10);
    } else {
        bpf_tail_call(skb as *const c_void, &jmp_table, 1);
    }

    sink(&mut p);

    vload!((*skb).len) as i32
}

#[inline(never)]
fn subprog_tail(skb: *const __sk_buff) -> i32 {
    let mut arr = [0u8; 64];
    let mut p = arr.as_mut_ptr();

    bpf_tail_call(skb as *const c_void, &jmp_table, 0);

    sink(&mut p);

    (vload!((*skb).len) * 2) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(skb: *const __sk_buff) -> i32 {
    let mut arr = [0u8; 128];
    let mut p = arr.as_mut_ptr();
    sink(&mut p);

    subprog_tail2(skb)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_1(skb: *const __sk_buff) -> i32 {
    let mut arr = [0u8; 128];
    let mut p = arr.as_mut_ptr();
    sink(&mut p);

    (vload!((*skb).len) * 3) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry(skb: *const __sk_buff) -> i32 {
    let mut arr = [0u8; 128];
    let mut p = arr.as_mut_ptr();
    sink(&mut p);

    subprog_tail(skb)
}

bpf_object!("GPL");
