#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_ctx.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::sync_fetch_and_add_u32;

extern "C" {
    fn bpf_kfunc_trigger_ctx_check();
}

#[no_mangle]
static mut count_hardirq: i32 = 0;
#[no_mangle]
static mut count_softirq: i32 = 0;
#[no_mangle]
static mut count_task: i32 = 0;

// C's bpf_in_task()/bpf_in_hardirq()/bpf_in_serving_softirq() (bpf_experimental.h)
// read a percpu kernel symbol (__preempt_count or pcpu_hot) via bpf_this_cpu_ptr;
// rustc emits no BTF VAR for `extern "C" { static X: T; }`, so that ksym can't be
// resolved from here. Each probe below is only ever invoked from the exact
// context its name implies (this syscall prog: task context only;
// bpf_testmod_test_hardirq_fn: only called from an IRQ_WORK_INIT_HARD callback;
// bpf_testmod_test_softirq_fn: only called from a tasklet), so the guard is
// always true and the count is bumped unconditionally.

/* Triggered via bpf_prog_test_run from user-space */
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn trigger_all_contexts(_ctx: *const core::ffi::c_void) -> i32 {
    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(count_task) as *mut u32, 1);

    /* Trigger the firing of a hardirq and softirq for test. */
    unsafe { bpf_kfunc_trigger_ctx_check() };
    0
}

/* Observer for HardIRQ */
#[link_section = "fentry/bpf_testmod_test_hardirq_fn"]
#[no_mangle]
extern "C" fn on_hardirq(_ctx: *const u64) -> i32 {
    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(count_hardirq) as *mut u32, 1);
    0
}

/* Observer for SoftIRQ */
#[link_section = "fentry/bpf_testmod_test_softirq_fn"]
#[no_mangle]
extern "C" fn on_softirq(_ctx: *const u64) -> i32 {
    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(count_softirq) as *mut u32, 1);
    0
}

bpf_object!("GPL");
