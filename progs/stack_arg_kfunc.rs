#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/stack_arg_kfunc.c
// (bpf-rs-core idiom).
//
// The C source is a #if/#else pair keyed on __BPF_FEATURE_STACK_ARGUMENT
// (only defined when the compiling LLVM's BPF backend supports stack-passed
// call arguments). This pipeline's LLVM does not: llc rejects the >5-arg
// kfunc calls from the #if branch with "too many arguments", and the
// clang-built reference object (stack_arg_kfunc.bpf.o.corig) confirms
// clang itself took the #else branch too (has_stack_arg rodata byte is
// 0x00, every prog is `w0 = 0; exit;`, no .maps section). Translate that
// branch: prog_tests/stack_arg.c's test_kfunc() skips entirely once
// skel->rodata->has_stack_arg reads false.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;

#[link_section = ".rodata"]
#[no_mangle]
static has_stack_arg: bool = false;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_scalar(_skb: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_ptr(_skb: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_mix(_skb: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_dynptr(_skb: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_mem(_skb: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_iter(_skb: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_const_str(_skb: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_timer(_skb: *const __sk_buff) -> i32 {
    0
}

bpf_object!("GPL");
