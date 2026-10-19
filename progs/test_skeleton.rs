// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/test_skeleton.c
// (bpf-rs-core idiom).
//
// prog_tests/skeleton.c drives every skeleton section by name: `.data`,
// `.bss`, `.rodata` (the const volatile anonymous struct `in`, read with
// read_volatile), the custom `.rodata.dyn` / `.data.dyn` / `.data.read_mostly`
// sections, `.data.non_mmapable` (a `__hidden` global and a static, which
// libbpf marks static and so leaves the map without BPF_F_MMAPABLE; the
// `.hidden` directive gives `zero_key` the C's STV_HIDDEN, the private
// `zero_value` keeps its C symbol name through `#[export_name]`), the
// `.kconfig` externs (`// BTF_KCONFIG:`, read back through
// `skel->kconfig`) and the 16 MiB `huge_arr` in `.bss`. `char` globals are
// `u8` with `// BTF_C_CHAR: u8`. C's `in4 __attribute__((aligned(64)))`
// has no Rust spelling for a scalar static; the consumer reads it by name
// only.
//
// `out5 = in5` is a 12-byte packed struct copy clang expands to byte
// moves; the same copy of the `#[repr(C, packed)]` struct is written as
// unaligned reads/writes of its two fields. The `in_dynarr` loop reads the
// const volatile `in_dynarr_sz` again every iteration, as C does, and
// indexes through raw pointers (no Rust bounds-check panic path).
// BTF_C_CHAR: u8

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_update_elem;
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

#[allow(non_camel_case_types)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct s {
    a: i32,
    b: i64,
}

/* .data section */
#[no_mangle]
static mut in1: i32 = -1;
#[no_mangle]
static mut in2: i64 = -1;

/* .bss section */
#[no_mangle]
static mut in3: u8 = 0;
#[no_mangle]
static mut in4: i64 = 0;
#[no_mangle]
static mut in5: s = s { a: 0, b: 0 };

/* .rodata section */
// clears the name in the object's BTF
// BTF_ANON
#[allow(non_camel_case_types)]
#[repr(C)]
struct __anon_type1 {
    in6: i32,
}
#[link_section = ".rodata"]
#[no_mangle]
static r#in: __anon_type1 = __anon_type1 { in6: 0 };

/* .data section */
#[no_mangle]
static mut out1: i32 = -1;
#[no_mangle]
static mut out2: i64 = -1;

/* .bss section */
#[no_mangle]
static mut out3: u8 = 0;
#[no_mangle]
static mut out4: i64 = 0;
#[no_mangle]
static mut out6: i32 = 0;

// BTF_KCONFIG: CONFIG_BPF_SYSCALL
// BTF_KCONFIG: LINUX_KERNEL_VERSION
extern "C" {
    static CONFIG_BPF_SYSCALL: u8; // bool
    static LINUX_KERNEL_VERSION: i32;
}
#[no_mangle]
static mut bpf_syscall: bool = false;
#[no_mangle]
static mut kern_ver: i32 = 0;

#[no_mangle]
static mut out5: s = s { a: 0, b: 0 };

#[link_section = ".rodata.dyn"]
#[no_mangle]
static in_dynarr_sz: i32 = 0;
#[link_section = ".rodata.dyn"]
#[no_mangle]
static in_dynarr: [i32; 4] = [-1, -2, -3, -4];

#[link_section = ".data.dyn"]
#[no_mangle]
static mut out_dynarr: [i32; 4] = [1, 2, 3, 4];

#[link_section = ".data.read_mostly"]
#[no_mangle]
static mut read_mostly_var: i32 = 0;
#[no_mangle]
static mut out_mostly_var: i32 = 0;

#[no_mangle]
static mut huge_arr: [u8; 16 * 1024 * 1024] = [0; 16 * 1024 * 1024];

/* non-mmapable custom .data section */

#[allow(non_camel_case_types)]
#[repr(C)]
struct my_value {
    x: i32,
    y: i32,
    z: i32,
}

// C: `__hidden int zero_key SEC(".data.non_mmapable");`
#[link_section = ".data.non_mmapable"]
#[no_mangle]
static mut zero_key: i32 = 0;
core::arch::global_asm!(".hidden zero_key");
// C: `static struct my_value zero_value SEC(".data.non_mmapable");`
#[link_section = ".data.non_mmapable"]
#[export_name = "zero_value"]
static mut zero_value: my_value = my_value { x: 0, y: 0, z: 0 };

#[link_section = ".maps"]
#[no_mangle]
static my_map: BpfMap<i32, my_value, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler(_ctx: *const c_void) -> i32 {
    unsafe {
        out1 = in1;
        out2 = in2;
        out3 = in3;
        out4 = in4;
        core::ptr::write_unaligned(addr_of_mut!(out5.a), core::ptr::read_unaligned(addr_of!(in5.a)));
        core::ptr::write_unaligned(addr_of_mut!(out5.b), core::ptr::read_unaligned(addr_of!(in5.b)));
        out6 = read_volatile(addr_of!(r#in.in6));

        bpf_syscall = CONFIG_BPF_SYSCALL != 0;
        kern_ver = LINUX_KERNEL_VERSION;

        let mut i: i32 = 0;
        while i < read_volatile(addr_of!(in_dynarr_sz)) {
            *(addr_of_mut!(out_dynarr) as *mut i32).add(i as usize) =
                read_volatile((addr_of!(in_dynarr) as *const i32).add(i as usize));
            i += 1;
        }

        out_mostly_var = read_mostly_var;

        huge_arr[huge_arr.len() - 1] = 123;

        /* make sure zero_key and zero_value are not optimized out */
        bpf_map_update_elem(&my_map, &*addr_of!(zero_key), &*addr_of!(zero_value), 0 /* BPF_ANY */);
    }

    0
}

bpf_object!("GPL");
