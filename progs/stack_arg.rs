#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/stack_arg.c
// (bpf-rs-core idiom).
//
// The C source is a #if/#else pair keyed on __BPF_FEATURE_STACK_ARGUMENT
// (only defined when the compiling LLVM's BPF backend supports stack-passed
// call arguments). This pipeline's LLVM does not (see stack_arg_kfunc.rs for
// the same finding), and the clang-built reference object for this file
// (selftests-output-qemu-lane1/stack_arg.bpf.o) confirms clang itself took
// the #else branch too: has_stack_arg's .rodata byte is 0x00 and every `tc`
// prog is exactly `w0 = 0; exit;` (2 insns). Translate that branch. The
// `.maps`/timer_map/timer_result globals are declared unconditionally in
// the C source (outside the #if), so they must be present regardless.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::maps::{self, BpfMap};

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

// struct timer_elem { struct bpf_timer timer; };
#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct timer_elem {
    timer: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static timer_map: BpfMap<i32, timer_elem, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut timer_result: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static has_stack_arg: bool = false;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_global_many_args(_ctx: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_bpf2bpf_ptr_stack_arg(_ctx: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_bpf2bpf_mix_stack_args(_ctx: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_bpf2bpf_nesting_stack_arg(_ctx: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_bpf2bpf_dynptr_stack_arg(_skb: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_two_callees(_ctx: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_async_cb_many_args(_ctx: *const __sk_buff) -> i32 {
    0
}

bpf_object!("GPL");
