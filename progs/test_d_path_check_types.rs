#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_d_path_check_types.c (bpf-rs-core
// idiom).
//
// Sibling of test_d_path_check_rdonly_mem.c and equally a must-be-rejected
// object: `active` points at REGULAR memory, which cannot be submitted to a
// ring buffer, so bpf_ringbuf_submit has to fail verification.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_per_cpu_ptr, bpf_ringbuf_submit};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

unsafe extern "C" {
    static bpf_prog_active: i32;
}

#[link_section = ".maps"]
#[no_mangle]
static ringbuf: BpfMap<(), (), { maps::RINGBUF }, 4096> = BpfMap::new();

#[link_section = "fentry/security_inode_getattr"]
#[no_mangle]
extern "C" fn d_path_check_rdonly_mem(_ctx: *const u64) -> i32 {
    let cpu = bpf_get_smp_processor_id();
    let active = bpf_per_cpu_ptr(
        core::ptr::addr_of!(bpf_prog_active) as *const c_void,
        cpu,
    );
    if !active.is_null() {
        // FAIL here: `active` points to 'regular' memory and cannot be
        // submitted to a ring buffer
        bpf_ringbuf_submit(active as *mut c_void, 0);
    }
    0
}

bpf_object!("GPL");
