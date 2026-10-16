// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// BTF_KSYM: runqueues
// BTF_KSYM: bpf_prog_active
// BTF_KSYM: bpf_link_fops1
// BTF_KSYM: bpf_link_fops2
// BTF_WEAK_KFUNC: invalid_kfunc

// Direct translation of tools/testing/selftests/bpf/progs/test_ksyms_weak.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_per_cpu_ptr, sink};
use btf_macros::btf;
use core::ffi::c_void;

#[btf]
struct rq {
    cpu: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct task_struct {
    _unused: [u8; 0],
}

extern "C" {
    static runqueues: rq;
    static bpf_prog_active: c_void;
    static bpf_link_fops1: c_void;
    static bpf_link_fops2: i32;

    fn bpf_task_acquire(p: *mut task_struct) -> *mut task_struct;
    fn bpf_testmod_test_mod_kfunc(i: i32);
    fn invalid_kfunc();
}

#[no_mangle]
static mut out__existing_typed: i32 = -1;
#[no_mangle]
static mut out__existing_typeless: u64 = u64::MAX;

#[no_mangle]
static mut out__non_existent_typeless: u64 = u64::MAX;
#[no_mangle]
static mut out__non_existent_typed: u64 = u64::MAX;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn pass_handler(_ctx: *const c_void) -> i32 {
    unsafe {
        // tests existing symbols. C's bpf_ksym_exists(&sym) is a run-time
        // test of the ld_imm64 address libbpf fills in (0 for a missing weak
        // ksym); rustc folds `addr_of!(static).is_null()` and a fn pointer's
        // null test to constants, so each address passes through sink()
        // (an asm barrier) before the test, which then compiles to the same
        // compare on the relocated value.
        let mut rq_addr = core::ptr::addr_of!(runqueues) as *mut c_void;
        sink(&mut rq_addr);
        let rq_ptr = bpf_per_cpu_ptr(rq_addr, 0) as *const rq;
        if !rq_ptr.is_null() && !rq_addr.is_null() {
            if let Some(cpu) = (*rq_ptr).cpu().get() {
                out__existing_typed = *cpu;
            }
        }
        out__existing_typeless = core::ptr::addr_of!(bpf_prog_active) as u64;

        // tests non-existent symbols.
        out__non_existent_typeless = core::ptr::addr_of!(bpf_link_fops1) as u64;

        // tests non-existent symbols.
        let mut fops2 = core::ptr::addr_of!(bpf_link_fops2) as *mut c_void;
        sink(&mut fops2);
        out__non_existent_typed = fops2 as u64;

        if !fops2.is_null() {
            /* can't happen */
            out__non_existent_typed = bpf_per_cpu_ptr(fops2, 0) as u64;
        }

        let mut acquire = bpf_task_acquire as usize as *mut c_void;
        sink(&mut acquire);
        if acquire.is_null() {
            /* dead code won't be seen by the verifier */
            bpf_task_acquire(core::ptr::null_mut());
        }

        let mut mod_kfunc = bpf_testmod_test_mod_kfunc as usize as *mut c_void;
        sink(&mut mod_kfunc);
        if mod_kfunc.is_null() {
            /* dead code won't be seen by the verifier */
            bpf_testmod_test_mod_kfunc(0);
        }

        let mut invalid = invalid_kfunc as usize as *mut c_void;
        sink(&mut invalid);
        if !invalid.is_null() {
            /* dead code won't be seen by the verifier */
            invalid_kfunc();
        }
    }
    0
}

bpf_object!("GPL");
