// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage)]
#![allow(non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/linked_vars1.c
// (bpf-rs-core idiom). Half of linked_vars.skel.h (Makefile.skel:
// `linked_vars.skel.h-deps := linked_vars1.bpf.o linked_vars2.bpf.o`):
// prog_tests/linked_vars.c fills the three input_bss* globals, triggers the
// raw tracepoint and checks each half's output_* sums. The other half's
// globals are externs here (`// BTF_EXTERN:`, scripts/ksym_vars.py mirrors
// the C object's declarations for the static linker); the weak ones are
// defined weak in both halves and this one's definitions win (the 10 and
// 100 the test expects). LINUX_KERNEL_VERSION and CONFIG_BPF_SYSCALL (weak
// here, strong in linked_vars2) are `.kconfig` externs (`// BTF_KCONFIG:`),
// bpf_link_fops a weak address-only ksym (`// BTF_KSYM:`); output_sink1
// keeps all three in use, as in the C. The `const volatile` .rodata
// globals are read with read_volatile. The C names its license global
// `LICENSE` (bpftool_ringbuf.rs). NO-ORACLE on its own: the gate swaps
// one object at a time and the linked skeleton takes the C other half.

use core::ffi::c_void;
use core::ptr::{addr_of, read_volatile};

use bpf_rs_core::bpf_object;

// BTF_KCONFIG: LINUX_KERNEL_VERSION
// BTF_KCONFIG: CONFIG_BPF_SYSCALL
// BTF_KSYM: bpf_link_fops
extern "C" {
    static LINUX_KERNEL_VERSION: i32;
    /* this weak extern will be strict due to the other file's strong extern */
    static CONFIG_BPF_SYSCALL: u8;
    static bpf_link_fops: u8; // extern const void __ksym __weak
}

#[no_mangle]
static mut input_bss1: i32 = 0;
#[no_mangle]
static mut input_data1: i32 = 1;
#[link_section = ".rodata"]
#[no_mangle]
static input_rodata1: i32 = 11;

#[linkage = "weak"]
#[no_mangle]
static mut input_bss_weak: i32 = 0;
/* these two definitions should win */
#[linkage = "weak"]
#[no_mangle]
static mut input_data_weak: i32 = 10;
#[linkage = "weak"]
#[link_section = ".rodata"]
#[no_mangle]
static input_rodata_weak: i32 = 100;

// BTF_EXTERN: input_bss2
// BTF_EXTERN: input_data2
// BTF_EXTERN: input_rodata2
extern "C" {
    static mut input_bss2: i32;
    static mut input_data2: i32;
    static input_rodata2: i32;
}

#[no_mangle]
static mut output_bss1: i32 = 0;
#[no_mangle]
static mut output_data1: i32 = 0;
#[no_mangle]
static mut output_rodata1: i32 = 0;

#[no_mangle]
static mut output_sink1: isize = 0;

#[inline(never)]
fn get_bss_res() -> i32 {
    /* just make sure all the relocations work against .text as well */
    unsafe { input_bss1.wrapping_add(input_bss2).wrapping_add(input_bss_weak) }
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler1(_ctx: *const c_void) -> i32 {
    unsafe {
        output_bss1 = get_bss_res();
        output_data1 = input_data1.wrapping_add(input_data2).wrapping_add(input_data_weak);
        output_rodata1 = read_volatile(addr_of!(input_rodata1))
            .wrapping_add(input_rodata2)
            .wrapping_add(read_volatile(addr_of!(input_rodata_weak)));

        /* make sure we actually use above special externs, otherwise compiler
         * will optimize them out
         */
        output_sink1 = (LINUX_KERNEL_VERSION.wrapping_add(CONFIG_BPF_SYSCALL as i32) as isize)
            .wrapping_add(addr_of!(bpf_link_fops) as isize);
    }
    0
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
