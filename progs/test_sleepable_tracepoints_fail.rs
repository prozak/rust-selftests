// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_sleepable_tracepoints_fail.c,
// bpf-rs-core idiom.
//
// A NEGATIVE test: a sleepable program (`tp_btf.s/...`) on sched_switch,
// a tracepoint that is not faultable, must fail to load; the kernel
// rejects it with the message declared below. The program body is empty,
// as in the C (BPF_PROG's preempt/prev/next arguments are unused).

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;

test_tags! {
    handle_sched_switch: __failure, __msg("Sleepable program cannot attach to non-faultable tracepoint");
}

#[link_section = "tp_btf.s/sched_switch"]
#[no_mangle]
extern "C" fn handle_sched_switch(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
