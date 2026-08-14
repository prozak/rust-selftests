#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_ksyms_btf_null_check.c
// (bpf-rs-core idiom).
//
// Must be REJECTED: `rq` comes back from bpf_per_cpu_ptr and is never
// null-checked, so dereferencing it is what the verifier has to catch. The
// `active` pointer IS checked first, which is what leaves the missing check
// on `rq` as the only reason for rejection — so both dereferences have to
// stay, in this order.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_per_cpu_ptr};
use btf_macros::btf;
use core::ffi::c_void;

unsafe extern "C" {
    static runqueues: c_void;
    static bpf_prog_active: i32;
}

#[btf]
struct rq {
    cpu: i32,
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler(_ctx: *const c_void) -> i32 {
    let cpu = bpf_get_smp_processor_id();
    let rq_p = bpf_per_cpu_ptr(core::ptr::addr_of!(runqueues), cpu) as *const rq;
    let active = bpf_per_cpu_ptr(
        core::ptr::addr_of!(bpf_prog_active) as *const c_void,
        cpu,
    ) as *const i32;
    if !active.is_null() {
        // READ_ONCE
        unsafe { core::ptr::read_volatile(active) };
        // !rq has NOT been tested, so the verifier should reject this
        let c = *unsafe { &*rq_p }.cpu().get().unwrap();
        core::hint::black_box(c);
    }
    0
}

bpf_object!("GPL");
