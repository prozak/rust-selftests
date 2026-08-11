#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_overhead.c
// (bpf-next), bpf-rs-core idiom.
//
// prog_tests/test_overhead.c never inspects any program's return value —
// it only measures /proc/self/comm write throughput with each program
// attached — but the C programs DO compute returns from their contexts
// (BPF_KPROBE/BPF_KRETPROBE read pt_regs fields directly, no CO-RE), so
// the translation mirrors them: x86_64 pt_regs slots per bpf_tracing.h,
// PARM1 = di (14*8), RC = ax (10*8); raw_tp ctx = u64 args[].

use bpf_rs_core::bpf_object;

const AX: usize = 10;
const DI: usize = 14;

#[link_section = "kprobe/__set_task_comm"]
#[no_mangle]
extern "C" fn prog1(ctx: *const u64) -> i32 {
    // return !tsk; tsk = PT_REGS_PARM1(ctx) = ctx->di
    let tsk = unsafe { *ctx.add(DI) };
    (tsk == 0) as i32
}

#[link_section = "kretprobe/__set_task_comm"]
#[no_mangle]
extern "C" fn prog2(ctx: *const u64) -> i32 {
    // return ret; ret = (int)PT_REGS_RC(ctx) = (int)ctx->ax
    unsafe { *ctx.add(AX) as i32 }
}

#[link_section = "raw_tp/task_rename"]
#[no_mangle]
extern "C" fn prog3(ctx: *const u64) -> i32 {
    // return !ctx->args[0];
    let arg0 = unsafe { *ctx };
    (arg0 == 0) as i32
}

#[link_section = "fentry/__set_task_comm"]
#[no_mangle]
extern "C" fn prog4(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "fexit/__set_task_comm"]
#[no_mangle]
extern "C" fn prog5(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
