#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_ptr_untrusted.c
// (bpf-rs-core idiom).
//
// BPF_PROG(lsm_run, int cmd, union bpf_attr *attr, unsigned int size,
// bool kernel): on BPF_RAW_TRACEPOINT_OPEN the program copies the
// tracepoint name in from user memory. `attr->raw_tracepoint.name` is at
// offset 0 of that union member; prog_tests/task_local_storage.c only
// checks that the program loads and that tp_name comes back, so the point
// of the test is that an UNTRUSTED pointer is accepted here at all.

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_copy_from_user;
use bpf_rs_core::progs::fentry_arg;
use core::ffi::c_void;

const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;

#[no_mangle]
static mut tp_name: [u8; 128] = [0; 128];

#[link_section = "lsm.s/bpf"]
#[no_mangle]
extern "C" fn lsm_run(ctx: *const u64) -> i32 {
    // C's parameter is `int cmd`, so the compare is 32-bit (`if w2 != 0x11`)
    let cmd = fentry_arg(ctx, 0) as u32;
    if cmd == BPF_RAW_TRACEPOINT_OPEN {
        let attr = fentry_arg(ctx, 1) as *const u64;
        // union bpf_attr's raw_tracepoint.name is the first member of that
        // arm, so the name pointer sits at offset 0
        let name = unsafe { core::ptr::read_volatile(attr) };
        bpf_copy_from_user(
            core::ptr::addr_of_mut!(tp_name) as *mut c_void,
            (core::mem::size_of::<[u8; 128]>() - 1) as u32,
            name as *const c_void,
        );
    }
    0
}

#[link_section = "raw_tracepoint"]
#[no_mangle]
extern "C" fn raw_tp_run(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
