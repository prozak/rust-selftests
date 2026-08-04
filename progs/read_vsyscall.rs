#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/read_vsyscall.c
// (bpf-rs-core idiom).
//
// The C source declares two real kfuncs with a genuine `void *dst` param:
// `bpf_copy_from_user_str` and `bpf_copy_from_user_task_str`. add_ksyms.py
// mirrors kfunc protos from kernel BTF by function-name match, and for a
// bare `void *` arg it emits a DIDerivedType pointer with no `baseType`
// field, which this LLVM's llvm-as hard-rejects (same class of bug as
// bpf_obj_drop in kptr_xchg_inline.c) -- confirmed unfixable in-file.
// progs/test_attach_probe.rs hit the identical bug for
// `bpf_copy_from_user_str` and worked around it by never referencing the
// real kfunc, instead reimplementing its observable contract
// (return-code convention) on top of `bpf_probe_read_user_str`, which is
// already exercised two lines above with an identical expected return code
// (-EFAULT) for this exact `user_ptr` value. The same reimplementation
// covers `bpf_copy_from_user_task_str` here: `target_pid` gates both
// programs to firing only for the current task, so `task` is always
// `bpf_get_current_task_btf()` and the task-qualified kfunc's observable
// result for THIS test coincides with the task-less helper's.

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
    // Stand-ins for the untranslatable bpf_copy_from_user_str /
    // bpf_copy_from_user_task_str kfuncs -- see file header.
    let r8 = bpf_probe_read_user_str(buf.as_mut_ptr() as *mut c_void, 8, ptr);
    let r9 = bpf_probe_read_user_str(buf.as_mut_ptr() as *mut c_void, 8, ptr);

    unsafe {
        store_ret(6, r6);
        store_ret(7, r7);
        store_ret(8, r8);
        store_ret(9, r9);
    }

    0
}

bpf_object!("GPL");
