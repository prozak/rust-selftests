#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/exhandler_kern.c,
// bpf-rs-core idiom.
//
// The C source deliberately dereferences task->task_works->func before
// checking task_works for null: for a newly-forked task, task_works is
// NULL, so work->func is a null-pointer-plus-offset load. The BPF verifier
// converts the CO-RE field access into a fault-tolerant PROBE_MEM load, so
// the load itself succeeds and yields 0 instead of faulting -- observing
// that zero is exactly what proves the kernel's exception handler ran. The
// two barrier_var() calls the C source uses stop the compiler from folding
// the two BTF-pointer null checks into one combined `btf_ptr | btf_ptr`
// comparison, which the verifier rejects; reused here via the existing
// bpf-rs-core barrier_var(&mut usize) helper on the pointers' bit patterns.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{barrier_var, bpf_get_current_pid_tgid};
use bpf_rs_core::progs::fentry_arg;
use btf_macros::btf;

#[btf]
struct callback_head {
    func: *const u8,
}

#[btf]
struct task_struct {
    task_works: *mut callback_head,
}

#[no_mangle]
static mut exception_triggered: u32 = 0;
#[no_mangle]
static mut test_pid: i32 = 0;

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn trace_task_newtask(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if unsafe { test_pid } != pid {
        return 0;
    }

    let task = fentry_arg(ctx, 0) as *mut task_struct;
    let task_ref = unsafe { &*task };

    let work: *mut callback_head = *task_ref.task_works().get().unwrap();
    let work_ref = unsafe { &*work };
    let func: *const u8 = *work_ref.func().get().unwrap();

    let mut work_bits = work as usize;
    barrier_var(&mut work_bits);
    if work_bits != 0 {
        return 0;
    }

    let mut func_bits = func as usize;
    barrier_var(&mut func_bits);
    if func_bits != 0 {
        return 0;
    }

    unsafe { exception_triggered += 1 };
    0
}

bpf_object!("GPL");
