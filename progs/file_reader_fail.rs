// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/file_reader_fail.c,
// bpf-rs-core idiom (file_reader.rs is the positive counterpart and has
// the same file-dynptr kfunc prototypes).
//
// Five NEGATIVE verifier tests on file dynptrs (prog_tests/file_reader.c
// RUN_TESTS this object): a file dynptr never discarded, discarding an xdp
// dynptr and an uninitialized one as a file dynptr, and reading from / a
// slice of a file dynptr after bpf_put_file() of the file it refers to.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_dynptr_read, bpf_get_current_task_btf};
use bpf_rs_core::test_tags;
use core::ffi::c_void;
use core::mem::MaybeUninit;

#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

// struct xdp_md (include/uapi/linux/bpf.h)
#[allow(non_camel_case_types)]
#[repr(C)]
struct xdp_md {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut user_ptr: *mut c_void = core::ptr::null_mut();

extern "C" {
    fn bpf_get_task_exe_file(task: *mut c_void) -> *mut c_void;
    fn bpf_put_file(file: *mut c_void);
    fn bpf_dynptr_from_file(file: *mut c_void, flags: u32, ptr: *mut c_void) -> i32;
    fn bpf_dynptr_file_discard(ptr: *mut c_void) -> i32;
    fn bpf_dynptr_from_xdp(xdp: *mut xdp_md, flags: u64, ptr__uninit: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(ptr: *const bpf_dynptr, offset: u64, buffer: *mut c_void, buffer_sz: u64) -> *mut c_void;
}

test_tags! {
    on_nanosleep_unreleased_ref: __failure, __msg("Unreleased reference id=");
    xdp_wrong_dynptr_type: __failure, __msg("Expected a dynptr of type file as R1");
    xdp_no_dynptr_type: __failure, __msg("Expected an initialized dynptr as R1");
    use_file_dynptr_after_put_file: __failure, __msg("Leaking reference id={{[0-9]+}} alloc_insn={{[0-9]+}}. Release it first.");
    use_file_dynptr_slice_after_put_file: __failure, __msg("Leaking reference id={{[0-9]+}} alloc_insn={{[0-9]+}}. Release it first.");
}

#[link_section = "lsm/file_open"]
#[no_mangle]
extern "C" fn on_nanosleep_unreleased_ref(_ctx: *mut c_void) -> i32 {
    let task: *mut c_void = bpf_get_current_task_btf();
    let file = unsafe { bpf_get_task_exe_file(task) };
    let mut dynptr = MaybeUninit::<bpf_dynptr>::uninit();

    if file.is_null() {
        return 0;
    }

    unsafe { err = bpf_dynptr_from_file(file, 0, dynptr.as_mut_ptr() as *mut c_void) };
    if unsafe { err } != 0 {
        1
    } else {
        0
    }
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_wrong_dynptr_type(xdp: *mut xdp_md) -> i32 {
    let mut dynptr = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_xdp(xdp, 0, dynptr.as_mut_ptr());
        bpf_dynptr_file_discard(dynptr.as_mut_ptr() as *mut c_void);
    }
    0
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_no_dynptr_type(_xdp: *mut xdp_md) -> i32 {
    let mut dynptr = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe { bpf_dynptr_file_discard(dynptr.as_mut_ptr() as *mut c_void) };
    0
}

#[link_section = "lsm/file_open"]
#[no_mangle]
extern "C" fn use_file_dynptr_after_put_file(_ctx: *mut c_void) -> i32 {
    let task: *mut c_void = bpf_get_current_task_btf();
    let file = unsafe { bpf_get_task_exe_file(task) };
    let mut dynptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buf = MaybeUninit::<[u8; 64]>::uninit();

    if file.is_null() {
        return 0;
    }

    unsafe {
        if bpf_dynptr_from_file(file, 0, dynptr.as_mut_ptr() as *mut c_void) == 0 {
            /* this should fail - file dynptr should be discarded first to prevent resource leak */
            bpf_put_file(file);

            bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, 64, dynptr.as_ptr(), 0, 0);
            return 0;
        }

        // out:
        bpf_dynptr_file_discard(dynptr.as_mut_ptr() as *mut c_void);
        bpf_put_file(file);
    }
    0
}

#[link_section = "lsm/file_open"]
#[no_mangle]
extern "C" fn use_file_dynptr_slice_after_put_file(_ctx: *mut c_void) -> i32 {
    let task: *mut c_void = bpf_get_current_task_btf();
    let file = unsafe { bpf_get_task_exe_file(task) };
    let mut dynptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buf = MaybeUninit::<[u8; 1]>::uninit();

    if file.is_null() {
        return 0;
    }

    unsafe {
        if bpf_dynptr_from_file(file, 0, dynptr.as_mut_ptr() as *mut c_void) == 0 {
            let data = bpf_dynptr_slice(dynptr.as_ptr(), 0, buf.as_mut_ptr() as *mut c_void, 1) as *const u8;
            if !data.is_null() {
                /* this should fail - file dynptr should be discarded first to prevent resource leak */
                bpf_put_file(file);

                return *data as i32;
            }
        }

        // out:
        bpf_dynptr_file_discard(dynptr.as_mut_ptr() as *mut c_void);
        bpf_put_file(file);
    }
    0
}

bpf_object!("GPL");
