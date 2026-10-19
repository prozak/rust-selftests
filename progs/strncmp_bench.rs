// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/strncmp_bench.c
// (bpf-rs-core idiom). benchs/bench_strncmp.c sets `cmp_str_len` in
// .rodata at open time, fills `str` through the skeleton's .bss, attaches
// one of the two tracepoint programs and reads `hits`: strncmp_no_helper
// compares `str` with the all-zero `target` byte by byte for cmp_str_len +
// 1 bytes, strncmp_helper calls bpf_strncmp for the same comparison. The
// `.rodata` order is the C's (`// C_LAYOUT:`): the 4096-byte `target` must
// be the last thing in .rodata for the verifier to accept it as a
// bpf_strncmp target (strncmp_test.rs). `barrier_var(target_str)` is
// black_box on the pointer (lesson 39). The strings are C `char` arrays.
// BTF_C_CHAR: u8
// C_LAYOUT: .rodata

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::hint::black_box;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_strncmp, sync_fetch_and_add};

const STRNCMP_STR_SZ: usize = 4096;

/* for user_space */
#[link_section = ".rodata"]
#[no_mangle]
static cmp_str_len: u32 = 1;
#[link_section = ".rodata"]
#[no_mangle]
static target: [u8; STRNCMP_STR_SZ] = [0; STRNCMP_STR_SZ];

#[no_mangle]
static mut hits: isize = 0;
#[no_mangle]
static mut str: [u8; STRNCMP_STR_SZ] = [0; STRNCMP_STR_SZ];

#[inline(always)]
fn local_strncmp(s1: *const u8, sz: u32, s2: *const u8) -> i32 {
    let mut ret: i32 = 0;
    let mut i: u32 = 0;

    while i < sz {
        /* E.g. 0xff > 0x31 */
        let c1 = unsafe { *s1.add(i as usize) };
        ret = c1 as i32 - unsafe { *s2.add(i as usize) } as i32;
        if ret != 0 || c1 == 0 {
            break;
        }
        i += 1;
    }

    ret
}

#[link_section = "tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn strncmp_no_helper(_ctx: *mut c_void) -> i32 {
    let target_str = black_box(addr_of!(target) as *const u8);

    let sz = unsafe { read_volatile(addr_of!(cmp_str_len)) }.wrapping_add(1);
    if local_strncmp(unsafe { addr_of_mut!(str) } as *const u8, sz, target_str) < 0 {
        sync_fetch_and_add(unsafe { addr_of_mut!(hits) }, 1);
    }
    0
}

#[link_section = "tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn strncmp_helper(_ctx: *mut c_void) -> i32 {
    let sz = unsafe { read_volatile(addr_of!(cmp_str_len)) }.wrapping_add(1);
    if bpf_strncmp(
        unsafe { addr_of_mut!(str) } as *const c_void,
        sz,
        addr_of!(target) as *const c_void,
    ) < 0
    {
        sync_fetch_and_add(unsafe { addr_of_mut!(hits) }, 1);
    }
    0
}

bpf_object!("GPL");
