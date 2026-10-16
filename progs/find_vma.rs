// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// BTF_C_CHAR: u8

// Direct translation of tools/testing/selftests/bpf/progs/find_vma.c,
// bpf-rs-core idiom. Sibling to find_vma_fail1.rs/find_vma_fail2.rs, which
// share the same task_struct/callback_ctx shape.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_find_vma, bpf_get_current_task_btf, bpf_probe_read_kernel_str};
use btf_macros::btf;

const VM_EXEC: u64 = 0x00000004;
const DNAME_INLINE_LEN: usize = 32;

#[btf]
struct task_struct {
    pid: i32,
}

// union shortname_store { unsigned char string[40]; long unsigned int words[5]; }:
// C's `d_iname` is `d_shortname.string`. A #[btf] struct stands in for the
// union (libbpf's CO-RE matching treats both as composites; bpf_iter_ipv6_route.rs).
#[btf]
struct shortname_store {
    string: [u8; 40],
}

#[btf]
struct dentry {
    d_shortname: shortname_store,
}

#[btf]
struct path {
    dentry: *mut dentry,
}

#[btf]
struct file {
    f_path: path,
}

#[btf]
struct vm_area_struct {
    vm_file: *mut file,
    vm_flags: u64,
}

#[allow(non_camel_case_types)]
struct callback_ctx {
    dummy: i32,
}

#[no_mangle]
static mut target_pid: i32 = 0;

#[no_mangle]
static mut d_iname: [u8; DNAME_INLINE_LEN] = [0; DNAME_INLINE_LEN];

#[no_mangle]
static mut found_vm_exec: u32 = 0;

#[no_mangle]
static mut addr: u64 = 0;

#[no_mangle]
static mut find_zero_ret: i32 = -1;

#[no_mangle]
static mut find_addr_ret: i32 = -1;

extern "C" fn check_vma(
    _task: *mut task_struct,
    vma: *mut vm_area_struct,
    _data: *mut callback_ctx,
) -> i64 {
    let vma_ref = unsafe { &*vma };

    let vm_file: *mut file = *vma_ref.vm_file().get().unwrap();
    if !vm_file.is_null() {
        let dentry_ptr: *mut dentry = *unsafe { &*vm_file }.f_path().dentry().get().unwrap();
        if !dentry_ptr.is_null() {
            let src = unsafe { &*dentry_ptr }.d_shortname().string().as_ptr() as *const c_void;
            unsafe {
                bpf_probe_read_kernel_str(
                    core::ptr::addr_of_mut!(d_iname) as *mut c_void,
                    (DNAME_INLINE_LEN - 1) as u32,
                    src,
                );
            }
        }
    }

    let vm_flags: u64 = *vma_ref.vm_flags().get().unwrap();
    if vm_flags & VM_EXEC != 0 {
        unsafe {
            found_vm_exec = 1;
        }
    }

    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handle_getpid(_ctx: *const c_void) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let pid = *unsafe { &*task }.pid().get().unwrap();
    if pid != unsafe { target_pid } {
        return 0;
    }

    let mut data = callback_ctx { dummy: 0 };
    let a = unsafe { addr };
    let ret = bpf_find_vma(task, a, check_vma, &mut data, 0);
    let zero_ret = bpf_find_vma(task, 0, check_vma, &mut data, 0);
    unsafe {
        find_addr_ret = ret as i32;
        find_zero_ret = zero_ret as i32;
    }
    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn handle_pe(_ctx: *const c_void) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let pid = *unsafe { &*task }.pid().get().unwrap();
    if pid != unsafe { target_pid } {
        return 0;
    }

    let mut data = callback_ctx { dummy: 0 };
    let a = unsafe { addr };
    let ret = bpf_find_vma(task, a, check_vma, &mut data, 0);
    let zero_ret = bpf_find_vma(task, 0, check_vma, &mut data, 0);
    unsafe {
        find_addr_ret = ret as i32;
        find_zero_ret = zero_ret as i32;
    }
    0
}

bpf_object!("GPL");
