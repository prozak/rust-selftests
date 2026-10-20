// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/raw_tp_null_fail.c
// (bpf-rs-core idiom). Every C program is an `asm volatile(...)` with
// __clobber_all followed by `return 0;`, so each one is carried here as a
// `// BPF_NAKED:` raw-asm body that matches the C object instruction by
// instruction (the asm text plus clang's `w0 = 0; exit`). The test_loader
// decl tags are declared with test_tags! (scripts/btf_test_tags.py).

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;

test_tags! {
    test_raw_tp_null_bpf_testmod_test_raw_tp_null_arg_1: __failure, __msg("R1 invalid mem access 'trusted_ptr_or_null_'");
    test_raw_tp_null_sched_pi_setprio_arg_2: __failure, __msg("R1 invalid mem access 'trusted_ptr_or_null_'");
    test_raw_tp_signal_generate_info_scalar: __success;
    test_tp_btf_signal_generate_info_scalar: __success;
    test_tp_btf_signal_generate_info_no_deref: __failure, __msg("R1 invalid mem access 'scalar'");
    test_tp_btf_signal_deliver_info_no_deref: __failure, __msg("R1 invalid mem access 'scalar'");
    test_raw_tp_null_sched_process_wait_arg_1: __failure, __msg("R1 invalid mem access 'trusted_ptr_or_null_'");
    test_raw_tp_null_sched_process_wait_arg_1_checked: __success;
}

/* Ensure module parameter has PTR_MAYBE_NULL */
#[no_mangle]
#[inline(never)]
#[link_section = "tp_btf/bpf_testmod_test_raw_tp_null_tp"]
// BPF_NAKED: test_raw_tp_null_bpf_testmod_test_raw_tp_null_arg_1
extern "C" fn test_raw_tp_null_bpf_testmod_test_raw_tp_null_arg_1() -> i32 {
    unsafe { core::arch::asm!("r1 = *(u64 *)(r1 +0);r1 = *(u64 *)(r1 +0);w0 = 0;exit;", options(noreturn)); }
}

/* Check NULL marking */
#[no_mangle]
#[inline(never)]
#[link_section = "tp_btf/sched_pi_setprio"]
// BPF_NAKED: test_raw_tp_null_sched_pi_setprio_arg_2
extern "C" fn test_raw_tp_null_sched_pi_setprio_arg_2() -> i32 {
    unsafe { core::arch::asm!("r1 = *(u64 *)(r1 +8);r1 = *(u64 *)(r1 +0);w0 = 0;exit;", options(noreturn)); }
}

/* Plain raw tracepoint arguments remain scalar values. */
#[no_mangle]
#[inline(never)]
#[link_section = "raw_tp/signal_generate"]
// BPF_NAKED: test_raw_tp_signal_generate_info_scalar
extern "C" fn test_raw_tp_signal_generate_info_scalar() -> i32 {
    unsafe { core::arch::asm!("r1 = *(u64 *)(r1 +8);if r1 != 1 goto +0;w0 = 0;exit;", options(noreturn)); }
}

/* tp_btf programs may inspect the sentinel as a scalar value. */
#[no_mangle]
#[inline(never)]
#[link_section = "tp_btf/signal_generate"]
// BPF_NAKED: test_tp_btf_signal_generate_info_scalar
extern "C" fn test_tp_btf_signal_generate_info_scalar() -> i32 {
    unsafe { core::arch::asm!("r1 = *(u64 *)(r1 +8);if r1 != 1 goto +0;w0 = 0;exit;", options(noreturn)); }
}

/* SEND_SIG_PRIV is non-NULL, so a NULL check cannot make info safe. */
#[no_mangle]
#[inline(never)]
#[link_section = "tp_btf/signal_generate"]
// BPF_NAKED: test_tp_btf_signal_generate_info_no_deref
extern "C" fn test_tp_btf_signal_generate_info_no_deref() -> i32 {
    unsafe { core::arch::asm!("r1 = *(u64 *)(r1 +8);if r1 == 0 goto +1;r1 = *(u32 *)(r1 +0);w0 = 0;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tp_btf/signal_deliver"]
// BPF_NAKED: test_tp_btf_signal_deliver_info_no_deref
extern "C" fn test_tp_btf_signal_deliver_info_no_deref() -> i32 {
    unsafe { core::arch::asm!("r1 = *(u64 *)(r1 +8);r1 = *(u32 *)(r1 +0);w0 = 0;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tp_btf/sched_process_wait"]
// BPF_NAKED: test_raw_tp_null_sched_process_wait_arg_1
extern "C" fn test_raw_tp_null_sched_process_wait_arg_1() -> i32 {
    unsafe { core::arch::asm!("r1 = *(u64 *)(r1 +0);r1 = *(u32 *)(r1 +0);w0 = 0;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tp_btf/sched_process_wait"]
// BPF_NAKED: test_raw_tp_null_sched_process_wait_arg_1_checked
extern "C" fn test_raw_tp_null_sched_process_wait_arg_1_checked() -> i32 {
    unsafe { core::arch::asm!("r1 = *(u64 *)(r1 +0);if r1 == 0 goto +1;r1 = *(u32 *)(r1 +0);w0 = 0;exit;", options(noreturn)); }
}

bpf_object!("GPL");
