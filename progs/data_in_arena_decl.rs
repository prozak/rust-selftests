// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/data_in_arena_decl.c
// (bpf-rs-core idiom). The `.arena.data` marker section tells libbpf to put
// .data, .bss and .rodata of the object into arena, after the `__arena`
// variables of the object (.addr_space.1) and in the arena map the object
// declares. prog_tests/data_in_arena.c's declared_arena subtest checks that
// there is exactly one arena map, sets counter through the skeleton before
// the load and runs use_data twice.
//
// `avar` is an `__arena` global: its ld_imm64 yields the arena user address
// and clang inserts addr_space_cast before each dereference. `cast_kern` is
// that instruction hand-encoded (verifier_arena_globals1, arena_atomics).

use core::ffi::c_void;

use bpf_rs_core::{bpf_map, bpf_object};

bpf_map! {
    arena {
        r#type: *const [i32; 33],      // BPF_MAP_TYPE_ARENA
        map_flags: *const [i32; 1024], // BPF_F_MMAPABLE
        max_entries: *const [i32; 4],
    }
}

// char data_in_arena SEC(".arena.data");
#[link_section = ".arena.data"]
#[no_mangle]
static mut data_in_arena: i8 = 0;

#[no_mangle]
static mut counter: i32 = 5;
#[no_mangle]
static mut sum: i64 = 0;
// const volatile int ro = 7;
#[link_section = ".rodata"]
#[no_mangle]
static ro: i32 = 7;

// int __arena avar = 11;
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
extern "C" fn use_data(_ctx: *mut c_void) -> i32 {
    unsafe {
        let av = cast_kern(core::ptr::addr_of_mut!(avar) as *mut u8) as *mut i32;
        let s = counter
            .wrapping_add(core::ptr::read_volatile(&ro))
            .wrapping_add(*av);
        sum = s as i64;
        counter = counter.wrapping_add(1);
        *av = (*av).wrapping_add(1);
        s
    }
}

bpf_object!("GPL");
