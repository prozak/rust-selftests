// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/copy_from_user_bprm.c
// (bpf-rs-core idiom). The sleepable LSM program copies the new image's
// argv/envp strings out of bprm->mm with the bpf_copy_from_user_mm kfuncs;
// the test reads the char arrays back as strings (BTF_C_CHAR).
// BTF_C_CHAR: u8

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use bpf_rs_core::progs::fentry_arg;
use btf_macros::btf;

#[btf]
struct mm_struct {}

#[btf]
struct linux_binprm {
    mm: *mut mm_struct,
    p: u64,
    argc: i32,
    envc: i32,
    exec: u64,
}

extern "C" {
    fn bpf_copy_from_user_mm(
        dst: *mut c_void,
        dst__sz: u32,
        unsafe_ptr__ign: *const c_void,
        mm: *mut mm_struct,
        flags: u64,
    ) -> i32;
    fn bpf_copy_from_user_mm_str(
        dst: *mut c_void,
        dst__sz: u32,
        unsafe_ptr__ign: *const c_void,
        mm: *mut mm_struct,
        flags: u64,
    ) -> i32;
}

const BPF_F_PAD_ZEROS: u64 = 1 << 0;
const EPERM: i32 = 1;

#[no_mangle]
static mut monitored_pid: i32 = 0;
#[no_mangle]
static mut bprm_argc: i32 = 0;
#[no_mangle]
static mut bprm_envc: i32 = 0;
#[no_mangle]
static mut data_len: i32 = 0;
#[no_mangle]
static mut invalid_flags_ret: i32 = 0;
#[no_mangle]
static mut copy_ret: i32 = 0;
#[no_mangle]
static mut arg0_ret: i32 = 0;
#[no_mangle]
static mut arg1_ret: i32 = 0;
#[no_mangle]
static mut env0_ret: i32 = 0;
#[no_mangle]
static mut env1_ret: i32 = 0;
#[no_mangle]
static mut data: [u8; 64] = [0; 64];
#[no_mangle]
static mut arg0: [u8; 32] = [0; 32];
#[no_mangle]
static mut arg1: [u8; 32] = [0; 32];
#[no_mangle]
static mut env0: [u8; 32] = [0; 32];
#[no_mangle]
static mut env1: [u8; 32] = [0; 32];

#[link_section = "lsm.s/bprm_check_security"]
#[no_mangle]
extern "C" fn check_exec_args(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    if pid != unsafe { monitored_pid } as u32 {
        return 0;
    }

    let bprm = unsafe { &*(fentry_arg(ctx, 0) as *const linux_binprm) };
    let mm = unsafe { *bprm.mm().as_ptr() };
    if mm.is_null() {
        return 0;
    }

    unsafe {
        bprm_argc = *bprm.argc().as_ptr();
        bprm_envc = *bprm.envc().as_ptr();

        let p = *bprm.p().as_ptr();
        /* this is the total size of args and envs starting from bprm->p */
        data_len = (*bprm.exec().as_ptr()).wrapping_sub(p) as i32;

        invalid_flags_ret =
            bpf_copy_from_user_mm(addr_of_mut!(data) as *mut c_void, 64, p as *const c_void, mm, !0u64);

        copy_ret = bpf_copy_from_user_mm(addr_of_mut!(data) as *mut c_void, 64, p as *const c_void, mm, 0);
        if copy_ret != 0 {
            return 0;
        }

        let mut offset: u64 = 0;
        /* arg0 is at bprm->p */
        arg0_ret = bpf_copy_from_user_mm_str(
            addr_of_mut!(arg0) as *mut c_void, 32, p.wrapping_add(offset) as *const c_void, mm, BPF_F_PAD_ZEROS);
        offset = offset.wrapping_add(arg0_ret as i64 as u64);

        /* arg1 is at bprm->p + arg0_ret */
        arg1_ret = bpf_copy_from_user_mm_str(
            addr_of_mut!(arg1) as *mut c_void, 32, p.wrapping_add(offset) as *const c_void, mm, BPF_F_PAD_ZEROS);
        offset = offset.wrapping_add(arg1_ret as i64 as u64);

        /* env0 is at bprm->p + arg0_ret + arg1_ret */
        env0_ret = bpf_copy_from_user_mm_str(
            addr_of_mut!(env0) as *mut c_void, 32, p.wrapping_add(offset) as *const c_void, mm, BPF_F_PAD_ZEROS);
        offset = offset.wrapping_add(env0_ret as i64 as u64);

        /* env1 is at bprm->p + arg0_ret + arg1_ret + env0_ret */
        env1_ret = bpf_copy_from_user_mm_str(
            addr_of_mut!(env1) as *mut c_void, 32, p.wrapping_add(offset) as *const c_void, mm, BPF_F_PAD_ZEROS);
    }

    -EPERM
}

bpf_object!("GPL");
