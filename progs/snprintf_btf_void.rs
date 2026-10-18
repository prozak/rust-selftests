// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/snprintf_btf_void.c
// (bpf-rs-core idiom). The test renders `obj` as the type id it stores in
// `type_id` and reads `ret` and `out` back; `out` must be a C `char`
// array in BTF for the skeleton (BTF_C_CHAR).
// BTF_C_CHAR: u8

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_snprintf_btf;

// struct btf_ptr from progs/btf_ptr.h (the selftests' own copy)
#[repr(C)]
struct btf_ptr {
    ptr: *mut c_void,
    type_id: u32,
    flags: u32,
}

#[no_mangle]
static mut type_id: u32 = 0;
/* A buffer we own to render the selected type from, kept in bounds. */
#[no_mangle]
static mut obj: [u8; 256] = [0; 256];
#[no_mangle]
static mut out: [u8; 64] = [0; 64];
#[no_mangle]
static mut ret: isize = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn dump_type(_ctx: *const c_void) -> i32 {
    let ptr = btf_ptr {
        ptr: core::ptr::addr_of_mut!(obj) as *mut c_void,
        type_id: unsafe { type_id },
        flags: 0,
    };

    unsafe {
        ret = bpf_snprintf_btf(
            core::ptr::addr_of_mut!(out) as *mut c_void,
            64,
            &ptr as *const btf_ptr as *const c_void,
            core::mem::size_of::<btf_ptr>() as u32,
            0,
        ) as isize;
    }
    0
}

bpf_object!("GPL");
