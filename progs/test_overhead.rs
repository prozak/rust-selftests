#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_overhead.c
// (bpf-next), bpf-rs-core idiom.
//
// prog_tests/test_overhead.c never inspects any program's return value or
// any global — it only measures /proc/self/comm write throughput with each
// program attached, so the bodies below only need to load and attach with
// the right SEC()/name; the actual ctx contents are never read.

use bpf_rs_core::bpf_object;

#[link_section = "kprobe/__set_task_comm"]
#[no_mangle]
extern "C" fn prog1(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "kretprobe/__set_task_comm"]
#[no_mangle]
extern "C" fn prog2(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "raw_tp/task_rename"]
#[no_mangle]
extern "C" fn prog3(_ctx: *const core::ffi::c_void) -> i32 {
    0
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
