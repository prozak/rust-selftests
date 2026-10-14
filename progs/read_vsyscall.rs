// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/read_vsyscall.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_copy_from_user, bpf_copy_from_user_task, bpf_get_current_pid_tgid,
    bpf_get_current_task_btf, bpf_probe_read, bpf_probe_read_kernel, bpf_probe_read_kernel_str,
    bpf_probe_read_str, bpf_probe_read_user, bpf_probe_read_user_str,
};
use core::ffi::c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
struct task_struct {
    _unused: [u8; 0],
}

// These are the kfuncs, the others are helpers.
extern "C" {
    fn bpf_copy_from_user_str(dst: *mut c_void, dst__sz: u32, unsafe_ptr: *const c_void, flags: u64) -> i32;
    fn bpf_copy_from_user_task_str(
        dst: *mut c_void,
        dst__sz: u32,
        unsafe_ptr: *const c_void,
        tsk: *mut task_struct,
        flags: u64,
    ) -> i32;
}

#[no_mangle]
static mut target_pid: i32 = 0;
// `void *user_ptr = 0;` in C. rustc has no genuine `void` type to give a raw
// pointer as pointee; `char` is the one primitive whose DWARF base-type
// encoding LLVM's BPF BTF-debug pass drops, so the pointer round-trips as
// BTF `PTR type_id=0` -- the real `void *` encoding. Same idiom as
// test_attach_probe.rs's `user_ptr`.
#[no_mangle]
static mut user_ptr: *mut char = core::ptr::null_mut();
#[no_mangle]
static mut read_ret: [i32; 10] = [0; 10];

unsafe fn store_ret(idx: usize, v: i64) {
    let p = core::ptr::addr_of_mut!(read_ret) as *mut i32;
    *p.add(idx) = v as i32;
}

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn do_probe_read(_ctx: *const u64) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) != unsafe { target_pid } as u64 {
        return 0;
    }

    let mut buf = [0u8; 8];
    let ptr = unsafe { user_ptr } as *const c_void;

    let r0 = bpf_probe_read_kernel(&mut buf, 8, ptr);
    let r1 = bpf_probe_read_kernel_str(buf.as_mut_ptr() as *mut c_void, 8, ptr);
    let r2 = bpf_probe_read(buf.as_mut_ptr() as *mut c_void, 8, ptr);
    let r3 = bpf_probe_read_str(buf.as_mut_ptr() as *mut c_void, 8, ptr);
    let r4 = bpf_probe_read_user(buf.as_mut_ptr() as *mut c_void, 8, ptr);
    let r5 = bpf_probe_read_user_str(buf.as_mut_ptr() as *mut c_void, 8, ptr);

    unsafe {
        store_ret(0, r0);
        store_ret(1, r1);
        store_ret(2, r2);
        store_ret(3, r3);
        store_ret(4, r4);
        store_ret(5, r5);
    }

    0
}

#[link_section = "fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn do_copy_from_user(_ctx: *const u64) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) != unsafe { target_pid } as u64 {
        return 0;
    }

    let mut buf = [0u8; 8];
    let ptr = unsafe { user_ptr } as *const c_void;
    let task = bpf_get_current_task_btf::<task_struct>();

    let r6 = bpf_copy_from_user(buf.as_mut_ptr() as *mut c_void, 8, ptr);
    let r7 = bpf_copy_from_user_task(buf.as_mut_ptr() as *mut c_void, 8, ptr, task, 0);
    let r8 = unsafe { bpf_copy_from_user_str(buf.as_mut_ptr() as *mut c_void, 8, ptr, 0) };
    let r9 = unsafe {
        bpf_copy_from_user_task_str(
            buf.as_mut_ptr() as *mut c_void,
            8,
            ptr,
            bpf_get_current_task_btf::<task_struct>(),
            0,
        )
    };

    unsafe {
        store_ret(6, r6);
        store_ret(7, r7);
        store_ret(8, r8 as i64);
        store_ret(9, r9 as i64);
    }

    0
}

bpf_object!("GPL");
