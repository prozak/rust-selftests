// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage)]
#![allow(non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/linked_vars2.c
// (bpf-rs-core idiom), the other half of linked_vars.skel.h: see
// linked_vars1.rs. This half's weak input_data_weak/input_rodata_weak lose
// to linked_vars1's; CONFIG_BPF_SYSCALL is the strong `.kconfig` extern
// (`// BTF_KCONFIG:`) that makes the pair strict, __start_BTF the
// address-only ksym (`// BTF_KSYM:`); output_sink2 is the C's `int`.
// NO-ORACLE on its own, as linked_vars1.

use core::ffi::c_void;
use core::ptr::{addr_of, read_volatile};

use bpf_rs_core::bpf_object;

// BTF_KCONFIG: LINUX_KERNEL_VERSION
// BTF_KCONFIG: CONFIG_BPF_SYSCALL
// BTF_KSYM: __start_BTF
extern "C" {
    static LINUX_KERNEL_VERSION: i32;
    /* when an extern is defined as both strong and weak, resulting symbol will be strong */
    static CONFIG_BPF_SYSCALL: u8;
    static __start_BTF: u8; // extern const void __ksym
}

#[no_mangle]
static mut input_bss2: i32 = 0;
#[no_mangle]
static mut input_data2: i32 = 2;
#[link_section = ".rodata"]
#[no_mangle]
static input_rodata2: i32 = 22;

#[linkage = "weak"]
#[no_mangle]
static mut input_bss_weak: i32 = 0;
/* these two weak variables should lose */
#[linkage = "weak"]
#[no_mangle]
static mut input_data_weak: i32 = 20;
#[linkage = "weak"]
#[link_section = ".rodata"]
#[no_mangle]
static input_rodata_weak: i32 = 200;

// BTF_EXTERN: input_bss1
// BTF_EXTERN: input_data1
// BTF_EXTERN: input_rodata1
extern "C" {
    static mut input_bss1: i32;
    static mut input_data1: i32;
    static input_rodata1: i32;
}

#[no_mangle]
static mut output_bss2: i32 = 0;
#[no_mangle]
static mut output_data2: i32 = 0;
#[no_mangle]
static mut output_rodata2: i32 = 0;

#[no_mangle]
static mut output_sink2: i32 = 0;

#[inline(never)]
fn get_data_res() -> i32 {
    /* just make sure all the relocations work against .text as well */
    unsafe { input_data1.wrapping_add(input_data2).wrapping_add(input_data_weak) }
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler2(_ctx: *const c_void) -> i32 {
    unsafe {
        output_bss2 = input_bss1.wrapping_add(input_bss2).wrapping_add(input_bss_weak);
        output_data2 = get_data_res();
        output_rodata2 = input_rodata1
            .wrapping_add(read_volatile(addr_of!(input_rodata2)))
            .wrapping_add(read_volatile(addr_of!(input_rodata_weak)));

        /* make sure we actually use above special externs, otherwise compiler
         * will optimize them out
         */
        output_sink2 = (LINUX_KERNEL_VERSION.wrapping_add(CONFIG_BPF_SYSCALL as i32) as isize)
            .wrapping_add(addr_of!(__start_BTF) as isize) as i32;
    }
    0
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
