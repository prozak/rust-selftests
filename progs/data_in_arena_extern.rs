// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/data_in_arena_extern.c
// (bpf-rs-core idiom). With the `.arena.data` marker the object's .data goes
// to arena, but `kp` holds the address of a variable of the kernel, which is
// not in arena: prog_tests/data_in_arena.c's ptr_to_extern subtest expects the
// open to fail. There is no skeleton.
//
// `bpf_prog_active` is an `extern const int ... __ksym` data symbol; the
// BTF VAR and .ksyms DATASEC for it come from scripts/ksym_vars.py.
// BTF_KSYM: bpf_prog_active

use core::ffi::c_void;

use bpf_rs_core::bpf_object;

// char data_in_arena SEC(".arena.data");
#[link_section = ".arena.data"]
#[no_mangle]
static mut data_in_arena: i8 = 0;

unsafe extern "C" {
    // extern const int bpf_prog_active __ksym;
    static bpf_prog_active: i32;
}

// const void *kp = &bpf_prog_active;
#[no_mangle]
static mut kp: *const c_void = core::ptr::addr_of!(bpf_prog_active) as *const c_void;

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn ptr_to_extern(_ctx: *mut c_void) -> i32 {
    unsafe { *(kp as *const i32) }
}

bpf_object!("GPL");
