// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/data_in_arena.c
// (bpf-rs-core idiom). The `.arena.data` marker puts .data, .bss and
// .rodata of the object into the arena map libbpf creates for them; the
// pointers stored in data (px, str, cpx, the ops table) become arena
// addresses, which is what prog_tests/data_in_arena.c checks through the
// skeleton (`skel->data->px == &skel->data->x`), together with the section
// alignment, the string sections that stay maps (`.rodata.str*`: helper
// arguments) and the callx through the function pointer in .data.rel.ro.
//
// the C's anonymous struct types (aligned64, ops), named here;
// scripts/btf_anon.py clears the names in the object's BTF
// BTF_ANON
// the C's `char` storage (hello, out, the format strings)
// BTF_C_CHAR: u8
// .data and .bss laid out as the C object has them (scripts/private_sections.py):
// the arena subtest compares bpf_map__initial_value()'s size with
// sizeof(*skel->data), and rustc's name order would end .data at 44 bytes
// where clang's declaration order ends it at 48
// C_LAYOUT: .data .bss

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_snprintf, bpf_strncmp, bpf_trace_printk, sync_fetch_and_add};

/* global data of the object is in arena */
#[link_section = ".arena.data"]
#[no_mangle]
static mut data_in_arena: u8 = 0;

#[no_mangle]
static mut counter: i32 = 5;
#[no_mangle]
static mut pair: [i64; 2] = [1, 2];
#[no_mangle]
static mut x: i32 = 42;
#[no_mangle]
static mut sum: i64 = 0;
#[no_mangle]
static mut table: [i64; 4] = [0; 4];

#[allow(non_camel_case_types)]
#[repr(C, align(64))]
struct __anon_type1 {
    v: [i64; 8],
}
#[no_mangle]
static mut aligned64: __anon_type1 = __anon_type1 { v: [0; 8] };

// const volatile int ro = 7;
#[link_section = ".rodata"]
#[no_mangle]
static ro: i32 = 7;
// const volatile long ro_table[4] = { 10, 20, 30, 40 };
#[link_section = ".rodata"]
#[no_mangle]
static ro_table: [i64; 4] = [10, 20, 30, 40];

/* const strings stay in a map for helpers and kfuncs, a copy of them is in arena */
#[link_section = ".rodata.str.hello"]
#[no_mangle]
static hello: [u8; 6] = *b"hello\0";

/* pointers to data that are stored in data */
#[no_mangle]
static mut px: *mut i32 = core::ptr::addr_of_mut!(x);
#[no_mangle]
static mut str: *const u8 = core::ptr::addr_of!(hello) as *const u8;
// int *const volatile cpx SEC(".data.rel.ro") = &x;
#[link_section = ".data.rel.ro"]
#[no_mangle]
static mut cpx: *mut i32 = core::ptr::addr_of_mut!(x);

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn use_data(_ctx: *mut c_void) -> i32 {
    unsafe {
        let mut i = 0;
        while i < 4 {
            table[i] = core::ptr::read_volatile(&ro_table[i]).wrapping_add(i as i64);
            i += 1;
        }
        sum = (counter.wrapping_add(core::ptr::read_volatile(&ro)) as i64)
            .wrapping_add(pair[0])
            .wrapping_add(pair[1]);
        counter = counter.wrapping_add(1);
        sync_fetch_and_add(core::ptr::addr_of_mut!(pair[1]) as *mut isize, 3);
        sum as i32
    }
}

// typedef int (*op_fn)(int);
type op_fn = extern "C" fn(i32) -> i32;

#[no_mangle]
#[inline(never)]
extern "C" fn add1(v: i32) -> i32 {
    v.wrapping_add(1)
}

/*
 * Pointers to functions and to data in read-only data of a program with callx.
 * Volatile, so that the compiler doesn't replace the pointers with what
 * they point to.
 */
#[allow(non_camel_case_types)]
#[repr(C)]
struct __anon_type2 {
    r#fn: op_fn,
    data: *mut i32,
    name: *const u8,
}
#[link_section = ".data.rel.ro"]
#[export_name = "ops"]
static mut ops: __anon_type2 = __anon_type2 {
    r#fn: add1,
    data: core::ptr::addr_of_mut!(x),
    name: core::ptr::addr_of!(hello) as *const u8,
};

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn use_ops(_ctx: *mut c_void) -> i32 {
    unsafe {
        /* a program has the arena when its code refers to it */
        counter = counter.wrapping_add(1);
        let f = core::ptr::read_volatile(core::ptr::addr_of!(ops.r#fn));
        let data = core::ptr::read_volatile(core::ptr::addr_of!(ops.data));
        let r = f(*data);
        let name = core::ptr::read_volatile(core::ptr::addr_of!(ops.name));
        r.wrapping_add(*name.add(1) as i8 as i32)
    }
}

/* the literal is in a map */
#[link_section = ".rodata.str1.1"]
static ABC: [u8; 4] = *b"abc\0";

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn use_ptrs(_ctx: *mut c_void) -> i32 {
    unsafe {
        let mut addr = core::ptr::addr_of_mut!(aligned64) as u64;
        let local: [u8; 4] = *b"abc\0";

        /* hide the address from the compiler, it knows that '& 63' is 0 */
        core::arch::asm!("/* {0} */", inout(reg) addr, options(nostack, preserves_flags));
        if addr & 63 != 0 {
            return 1;
        }
        aligned64.v[7] = 7;
        if *px != 42 {
            return 2;
        }
        *px = 43;
        if x != 43 || *core::ptr::read_volatile(core::ptr::addr_of!(cpx)) != 43 {
            return 3;
        }
        if *str != b'h' || *str.add(4) != b'o' || *str.add(5) != 0 {
            return 4;
        }
        /* the literal is in a map */
        if bpf_strncmp(local.as_ptr() as *const c_void, 4, ABC.as_ptr() as *const c_void) != 0 {
            return 5;
        }
    }
    0
}

#[no_mangle]
static mut out: [u8; 16] = [0; 16];

/* format strings are in a map */
#[link_section = ".rodata.str"]
static FMT_PRINTK: [u8; 11] = *b"counter %d\0";
#[link_section = ".rodata.str"]
static FMT_SNPRINTF: [u8; 6] = *b"%d-%d\0";

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn use_printk(_ctx: *mut c_void) -> i32 {
    let mut buf = core::mem::MaybeUninit::<[u8; 16]>::uninit();

    unsafe {
        bpf_trace_printk(FMT_PRINTK.as_ptr() as *const c_void, 11, counter as i64 as u64, 0, 0);
        let args: [u64; 2] = [x as i64 as u64, core::ptr::read_volatile(&ro) as i64 as u64];
        let n = bpf_snprintf(
            buf.as_mut_ptr() as *mut c_void,
            16,
            FMT_SNPRINTF.as_ptr() as *const c_void,
            args.as_ptr() as *const c_void,
            16,
        );
        let buf = buf.assume_init();
        let mut i = 0;
        while i < 16 {
            out[i] = buf[i];
            i += 1;
        }
        n as i32
    }
}

bpf_object!("GPL");
