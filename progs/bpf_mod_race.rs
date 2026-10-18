// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_mod_race.c
// (bpf-rs-core idiom). prog_tests/bpf_mod_race.c fills the read-only config
// through the skeleton before the load (the loading thread's tgid, the
// error to inject into the module's init, the userfaultfd-monitored page),
// then races a bpf_testmod load against a program load: widen_race blocks
// the module's init in bpf_copy_from_user on that page, and the test checks
// bpf_blocking and res_try_get_module. `task->tgid` is a CO-RE read.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_copy_from_user, bpf_get_current_task_btf};
use btf_macros::btf;

// the C's anonymous config struct type, named here; scripts/btf_anon.py
// clears the name in the object's BTF
// BTF_ANON
#[allow(non_camel_case_types)]
#[repr(C)]
struct __anon_type1 {
    /* thread to activate trace programs for */
    tgid: i32,
    /* return error from __init function */
    inject_error: i32,
    /* uffd monitored range start address */
    fault_addr: *mut c_void,
}
unsafe impl Sync for __anon_type1 {}

#[link_section = ".rodata"]
#[no_mangle]
static bpf_mod_race_config: __anon_type1 = __anon_type1 {
    tgid: -1,
    inject_error: 0,
    fault_addr: core::ptr::null_mut(),
};

#[no_mangle]
static mut bpf_blocking: i32 = 0;
#[no_mangle]
static mut res_try_get_module: i32 = -1;

#[btf]
struct task_struct {
    tgid: i32,
}

#[inline(always)]
fn check_thread_id() -> bool {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let tgid = *unsafe { &*task }.tgid().get().unwrap();

    tgid == unsafe { core::ptr::read_volatile(core::ptr::addr_of!(bpf_mod_race_config.tgid)) }
}

#[link_section = "fmod_ret.s/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn widen_race(_ctx: *const u64) -> i32 {
    let mut dst = core::mem::MaybeUninit::<i8>::uninit();

    if !check_thread_id() {
        return 0;
    }
    unsafe {
        /* Indicate that we will attempt to block */
        bpf_blocking = 1;
        bpf_copy_from_user(
            dst.as_mut_ptr() as *mut c_void,
            1,
            core::ptr::read_volatile(core::ptr::addr_of!(bpf_mod_race_config.fault_addr)) as *const c_void,
        );
        core::ptr::read_volatile(core::ptr::addr_of!(bpf_mod_race_config.inject_error))
    }
}

#[link_section = "fexit/do_init_module"]
#[no_mangle]
extern "C" fn fexit_init_module(_ctx: *const u64) -> i32 {
    if !check_thread_id() {
        return 0;
    }
    /* Indicate that we finished blocking */
    unsafe { bpf_blocking = 2 };
    0
}

#[link_section = "fexit/btf_try_get_module"]
#[no_mangle]
extern "C" fn fexit_module_get(ctx: *const u64) -> i32 {
    /* BPF_PROG(fexit_module_get, const struct btf *btf, struct module *mod) */
    let module = unsafe { *ctx.add(1) };

    unsafe { res_try_get_module = (module != 0) as i32 };
    0
}

bpf_object!("GPL");
