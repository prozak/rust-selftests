// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/data_in_arena_fail.c
// (bpf-rs-core idiom). With the `.arena.data` marker the object's .data goes
// to arena, but `pp` points into `.data.rel.ro`, read-only data with pointers
// that stays a map: prog_tests/data_in_arena.c's ptr_to_map subtest opens the
// skeleton and expects the load to fail.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;

// char data_in_arena SEC(".arena.data");
#[link_section = ".arena.data"]
#[no_mangle]
static mut data_in_arena: i8 = 0;

#[no_mangle]
static mut x: i32 = 42;

// int *const volatile tbl[1] SEC(".data.rel.ro") = { &x };
#[link_section = ".data.rel.ro"]
#[no_mangle]
static mut tbl: [*mut i32; 1] = [core::ptr::addr_of_mut!(x)];

// int *const volatile *pp = tbl;
#[no_mangle]
static mut pp: *const *mut i32 = core::ptr::addr_of!(tbl) as *const *mut i32;

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn ptr_to_map(_ctx: *mut c_void) -> i32 {
    unsafe { *core::ptr::read_volatile(pp) }
}

bpf_object!("GPL");
