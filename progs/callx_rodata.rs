// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/callx_rodata.c
// (bpf-rs-core idiom). Two programs call through a table of function
// pointers in .rodata (callx); prog_tests/callx_rodata_lskel.c loads the
// object through its light skeleton after setting bias in .rodata, and runs
// each program for its return value. The table is read with volatile loads
// so the calls stay indirect, as the C's `const volatile` table keeps them;
// `ops`, add_bias and mul3 are the C object's local symbols. .rodata is
// laid out as the C object has it (bias, skip, ops).
// C_LAYOUT: .rodata

use core::ffi::c_void;
use core::ptr::{addr_of, read_volatile};

use bpf_rs_core::bpf_object;

/* set by user space before the programs are loaded, it's in .rodata too */
#[link_section = ".rodata"]
#[no_mangle]
static bias: i32 = 1;

#[no_mangle]
static mut op_idx: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static skip: bool = false;

type OpFn = extern "C" fn(i32) -> i32;

#[inline(never)]
#[export_name = "add_bias"]
extern "C" fn add_bias(x: i32) -> i32 {
    x.wrapping_add(unsafe { read_volatile(&bias) })
}

#[inline(never)]
#[export_name = "mul3"]
extern "C" fn mul3(x: i32) -> i32 {
    x.wrapping_mul(3)
}

/* volatile, so that the compiler doesn't replace the table with direct calls */
#[link_section = ".rodata"]
#[export_name = "ops"]
static ops: [OpFn; 2] = [add_bias, mul3];

#[link_section = "socket"]
#[no_mangle]
extern "C" fn select_op(_ctx: *mut c_void) -> i32 {
    let i = unsafe { op_idx } as u32;

    if i >= 2 {
        return -1;
    }
    let op = unsafe { read_volatile(addr_of!(ops).cast::<OpFn>().add(i as usize)) };
    op(10)
}

/* functions have other offsets in this program */
#[link_section = "socket"]
#[no_mangle]
extern "C" fn both_ops(_ctx: *mut c_void) -> i32 {
    let op1 = unsafe { read_volatile(addr_of!(ops).cast::<OpFn>().add(1)) };
    let op0 = unsafe { read_volatile(addr_of!(ops).cast::<OpFn>()) };
    op1(op0(4))
}

/* no callx here */
#[link_section = "socket"]
#[no_mangle]
extern "C" fn read_bias(_ctx: *mut c_void) -> i32 {
    unsafe { read_volatile(&bias) }
}

bpf_object!("GPL");
