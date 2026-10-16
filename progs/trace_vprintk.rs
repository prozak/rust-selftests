// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/trace_vprintk.c
// (bpf-rs-core idiom).
//
// bpf_printk("\t") with no arguments is bpf_trace_printk(fmt, sizeof fmt);
// __bpf_vprintk(fmt, 11 args) puts the promoted arguments in a [u64; 11] on
// the stack and calls bpf_trace_vprintk(fmt, sizeof fmt, args, sizeof args)
// (test_tunnel_kern.rs). The five one-character strings are .rodata statics
// whose addresses are the %s arguments.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_trace_printk, bpf_trace_vprintk};
use core::ffi::c_void;
use core::ptr::null;

#[no_mangle]
static mut null_data_vprintk_ret: i32 = 0;
#[no_mangle]
static mut trace_vprintk_ret: i32 = 0;
#[no_mangle]
static mut trace_vprintk_ran: i32 = 0;

static ONE: [u8; 2] = *b"1\0";
static THREE: [u8; 2] = *b"3\0";
static FIVE: [u8; 2] = *b"5\0";
static SEVEN: [u8; 2] = *b"7\0";
static NINE: [u8; 2] = *b"9\0";
static F: [u8; 5] = *b"%pS\n\0";
static TAB: [u8; 2] = *b"\t\0";
static FMT: [u8; 34] = *b"%s,%d,%s,%d,%s,%d,%s,%d,%s,%d %d\n\0";

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn sys_enter(_ctx: *const c_void) -> i32 {
    unsafe {
        /* runner doesn't search for \t, just ensure it compiles */
        bpf_trace_printk(TAB.as_ptr() as *const c_void, TAB.len() as u32, 0, 0, 0);

        trace_vprintk_ran += 1;
        let args: [u64; 11] = [
            ONE.as_ptr() as u64,
            2,
            THREE.as_ptr() as u64,
            4,
            FIVE.as_ptr() as u64,
            6,
            SEVEN.as_ptr() as u64,
            8,
            NINE.as_ptr() as u64,
            10,
            trace_vprintk_ran as u64,
        ];
        trace_vprintk_ret = bpf_trace_vprintk(
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            args.as_ptr() as *const c_void,
            core::mem::size_of_val(&args) as u32,
        ) as i32;

        /* non-NULL fmt w/ NULL data should result in error */
        null_data_vprintk_ret =
            bpf_trace_vprintk(F.as_ptr() as *const c_void, F.len() as u32, null(), 0) as i32;
    }
    0
}

bpf_object!("GPL");
