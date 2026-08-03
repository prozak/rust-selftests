#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_task_pt_regs.c
// (bpf-rs-core idiom).
//
// PT_REGS_SIZE = sizeof(struct pt_regs) on x86_64 = 168 bytes (21
// `unsigned long` slots, same layout documented in test_uprobe.rs /
// test_probe_user.rs). The C source never interprets the bytes -- it just
// bpf_probe_read_kernel()s the raw struct twice (once via
// bpf_task_pt_regs(), once via ctx) and lets userspace memcmp() the two
// buffers -- so both `ctx` and the `bpf_task_pt_regs()` return value stay
// opaque `*const c_void` here; no field-typed `pt_regs` struct is needed.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_task_btf, bpf_probe_read_kernel, bpf_task_pt_regs};
use core::ffi::c_void;

const PT_REGS_SIZE: u32 = 168;

#[no_mangle]
static mut current_regs: [u8; PT_REGS_SIZE as usize] = [0; PT_REGS_SIZE as usize];
#[no_mangle]
static mut ctx_regs: [u8; PT_REGS_SIZE as usize] = [0; PT_REGS_SIZE as usize];
#[no_mangle]
static mut uprobe_res: i32 = 0;

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe(ctx: *const c_void) -> i32 {
    let current: *mut c_void = bpf_get_current_task_btf();
    let regs = bpf_task_pt_regs(current) as *const c_void;

    unsafe {
        if bpf_probe_read_kernel(&mut *core::ptr::addr_of_mut!(current_regs), PT_REGS_SIZE, regs)
            != 0
        {
            return 0;
        }
        if bpf_probe_read_kernel(&mut *core::ptr::addr_of_mut!(ctx_regs), PT_REGS_SIZE, ctx) != 0
        {
            return 0;
        }

        // Prove that uprobe was run
        uprobe_res = 1;
    }

    0
}

bpf_object!("GPL");
