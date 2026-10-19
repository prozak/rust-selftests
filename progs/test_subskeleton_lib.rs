// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage)]
#![allow(non_upper_case_globals)]

// translint allow(padding): var3 is a zero-initialised .bss global the
// consumer writes through the subskeleton, never a Rust literal
// translint: allow(padding)

// Direct translation of
// tools/testing/selftests/bpf/progs/test_subskeleton_lib.c (bpf-rs-core
// idiom). The library half of test_subskeleton.skel.h and
// test_subskeleton_lib.skel.h (Makefile.skel): prog_tests/subskeleton.c
// opens test_subskeleton_lib.subskel.h over the loaded object, writes
// `var1`, `var2` and `var3` through it, and reads `libout1`, `var5`,
// `var6` and the kconfig back; it also looks `lib_perf_handler` and
// `map1` up by name.
//
// `var6` and `map2` are test_subskeleton_lib2.c's (`// BTF_EXTERN:`,
// scripts/ksym_vars.py mirrors the C object's extern declarations for the
// static linker; the extern map's anonymous definition struct is mirrored
// with its members). `var5` is the C's `__weak int var5 SEC(".data")`,
// which test_subskeleton.c's strong definition overrides; `var7` lives in
// the C's `.data.custom` (scripts/private_sections.py). `var3`'s type is
// the C's anonymous struct (`// BTF_ANON:`). CONFIG_BPF_SYSCALL is the
// `.kconfig` extern (`// BTF_KCONFIG:`), `extern volatile bool` in the C
// so `(void) CONFIG_BPF_SYSCALL;` is a real load. `var1` is `const
// volatile` and `var2` `volatile`: read_volatile. `lib_routine` is the
// C's global function in .text, called from test_subskeleton.c. The C
// names its license global `LICENSE` (bpftool_ringbuf.rs).
// BTF_ANON: var3_t
// BTF_FN_PTR: fn_ptr = lib_routine

use core::ffi::c_void;
use core::ptr::{addr_of, read_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_update_elem;
use bpf_rs_core::maps::{self, BpfMap};

const BPF_ANY: u64 = 0;

/* volatile to force a read */
#[link_section = ".rodata"]
#[no_mangle]
static var1: i32 = 0;
#[no_mangle]
static mut var2: i32 = 1;

#[allow(non_camel_case_types)]
#[repr(C)]
struct var3_t {
    var3_1: i32,
    var3_2: i64,
}
#[no_mangle]
static mut var3: var3_t = var3_t { var3_1: 0, var3_2: 0 };
#[no_mangle]
static mut libout1: i32 = 0;

// BTF_KCONFIG: CONFIG_BPF_SYSCALL
extern "C" {
    static CONFIG_BPF_SYSCALL: u8;
}

#[no_mangle]
static mut var4: [i32; 4] = [0; 4];

#[linkage = "weak"]
#[link_section = ".data"]
#[no_mangle]
static mut var5: i32 = 0;

/* Fully contained within library extern-and-definition */
// BTF_EXTERN: var6
extern "C" {
    static var6: i32;
}

#[link_section = ".data.custom"]
#[no_mangle]
static mut var7: i32 = 0;

// C's `int (*fn_ptr)(void);`, a NULL in .bss: a pointer with lib_routine's
// prototype in BTF (`// BTF_FN_PTR:` below, scripts/btf_fn_ptrs.py)
#[no_mangle]
static mut fn_ptr: *const c_void = core::ptr::null();

#[link_section = ".maps"]
#[no_mangle]
static map1: BpfMap<u32, u32, { maps::HASH }, 16> = BpfMap::new();

// BTF_EXTERN: map2
extern "C" {
    static map2: BpfMap<u32, u32, { maps::HASH }, 16>;
}

#[no_mangle]
pub extern "C" fn lib_routine() -> i32 {
    let key: u32 = 1;
    let value: u32 = 2;

    unsafe {
        read_volatile(addr_of!(CONFIG_BPF_SYSCALL));
        bpf_map_update_elem(addr_of!(map2), &key, &value, BPF_ANY);

        libout1 = (read_volatile(addr_of!(var1))
            .wrapping_add(read_volatile(addr_of!(var2)))
            .wrapping_add(var3.var3_1) as i64)
            .wrapping_add(var3.var3_2)
            .wrapping_add(var5 as i64)
            .wrapping_add(var6 as i64) as i32;
        libout1
    }
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn lib_perf_handler(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
