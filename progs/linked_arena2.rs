// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/linked_arena2.c
// (bpf-rs-core idiom). Half of linked_arena.skel.h (Makefile.skel:
// `linked_arena.skel.h-deps := linked_arena1.bpf.o linked_arena2.bpf.o`):
// prog_tests/linked_externs.c's skel_arena subtest runs bump2 after sum1
// and expects 33 back and 11/22 in the arena; relink_arena links the two
// .bpf.o files by name and checks every `.addr_space.1` extern resolved.
//
// `b_val` is this half's `__arena_global` (section `.addr_space.1`),
// `a_val` linked_arena1's (`// BTF_EXTERN:`, scripts/ksym_vars.py mirrors
// the C object's extern VAR in the `.addr_space.1` DATASEC). The arena
// map itself is linked_arena1's; this object has none, like the C
// (data_in_arena_nomap.rs). Each dereference is the C's addr_space_cast,
// hand-encoded as `cast_kern` (data_in_arena_decl.rs).

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::bpf_object;

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut b_val: i64 = 2;
// BTF_EXTERN: a_val
extern "C" {
    static mut a_val: i64; /* defined in linked_arena1.c */
}

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
extern "C" fn bump2(_ctx: *mut c_void) -> i32 {
    unsafe {
        let a = cast_kern(addr_of_mut!(a_val) as *mut u8) as *mut i64;
        let b = cast_kern(addr_of_mut!(b_val) as *mut u8) as *mut i64;
        *a = (*a).wrapping_add(10);
        *b = (*b).wrapping_add(20);
        (*a).wrapping_add(*b) as i32
    }
}

bpf_object!("GPL");
