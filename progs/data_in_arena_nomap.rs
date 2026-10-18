// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/data_in_arena_nomap.c
// (bpf-rs-core idiom). The object has an `__arena` global (.addr_space.1) and
// the `.arena.data` marker but declares no arena map, and the one libbpf
// creates for the data sections will not do: prog_tests/data_in_arena.c's
// arena_var_no_map subtest expects the open to fail. There is no skeleton.
//
// `cast_kern` is the addr_space_cast clang inserts before the `__arena`
// dereference, hand-encoded (data_in_arena_decl, verifier_arena_globals1).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;

// char data_in_arena SEC(".arena.data");
#[link_section = ".arena.data"]
#[no_mangle]
static mut data_in_arena: i8 = 0;

#[no_mangle]
static mut counter: i32 = 5;

// int __arena_global avar = 11;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut avar: i32 = 11;

/// `bpf_addr_space_cast(ptr, 0, 1)`: in-place single-register encoding.
#[inline(always)]
unsafe fn cast_kern(p: *mut u8) -> *mut u8 {
    let mut p = p;
    core::arch::asm!(
        ".byte 0xBF",
        ".ifc {0}, r0", ".byte 0x00", ".endif",
        ".ifc {0}, r1", ".byte 0x11", ".endif",
        ".ifc {0}, r2", ".byte 0x22", ".endif",
        ".ifc {0}, r3", ".byte 0x33", ".endif",
        ".ifc {0}, r4", ".byte 0x44", ".endif",
        ".ifc {0}, r5", ".byte 0x55", ".endif",
        ".ifc {0}, r6", ".byte 0x66", ".endif",
        ".ifc {0}, r7", ".byte 0x77", ".endif",
        ".ifc {0}, r8", ".byte 0x88", ".endif",
        ".ifc {0}, r9", ".byte 0x99", ".endif",
        ".short 1",
        ".long 1",
        inout(reg) p,
        options(nostack, preserves_flags),
    );
    p
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arena_var(_ctx: *mut c_void) -> i32 {
    unsafe {
        let av = cast_kern(core::ptr::addr_of_mut!(avar) as *mut u8) as *mut i32;
        (*av).wrapping_add(counter)
    }
}

bpf_object!("GPL");
