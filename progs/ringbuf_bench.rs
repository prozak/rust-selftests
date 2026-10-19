// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/ringbuf_bench.c
// (bpf-rs-core idiom). benchs/bench_ringbufs.c (rb-libbpf, rb-custom)
// sets `batch_cnt`, `use_output`, `bench_producer` and `wakeup_data_size`
// in .rodata at open time, attaches the fentry program and counts the
// samples its consumer receives against `dropped` and `hits`: the program
// reserves/submits (or outputs) `sample_val` batch_cnt times per
// getpgid(), with the wakeup flags get_flags() derives from the ring's
// fill level. The `const volatile` .rodata globals are re-read at every
// use, as clang does; `bench_producer` is the C's `bool`, declared u8
// (translint bool-global) and tested as clang tests it: `== 1` where it
// selects the flags, `!= 0` where it gates the hit count (lesson 32).
// `dropped` and `hits` are 128-byte aligned in the C (`// C_LAYOUT:` keeps
// the C's .bss and .rodata layouts).
// C_LAYOUT: .bss .rodata

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use bpf_rs_core::helpers::{
    bpf_ringbuf_output, bpf_ringbuf_query, bpf_ringbuf_reserve, bpf_ringbuf_submit,
    sync_fetch_and_add,
};
use bpf_rs_core::maps;
use bpf_rs_core::{bpf_map, bpf_object};

const BPF_RB_NO_WAKEUP: isize = 1;
const BPF_RB_FORCE_WAKEUP: isize = 2;
const BPF_RB_AVAIL_DATA: u64 = 0;

bpf_map! {
    ringbuf {
        r#type: *const [i32; maps::RINGBUF],
    }
}

#[link_section = ".rodata"]
#[no_mangle]
static batch_cnt: i32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static use_output: isize = 0;
#[link_section = ".rodata"]
#[no_mangle]
static bench_producer: u8 = 0;

#[no_mangle]
static mut sample_val: isize = 42;
#[no_mangle]
static mut dropped: isize = 0;
#[no_mangle]
static mut hits: isize = 0;

#[link_section = ".rodata"]
#[no_mangle]
static wakeup_data_size: isize = 0;

#[inline(always)]
fn get_flags() -> isize {
    unsafe {
        if read_volatile(addr_of!(bench_producer)) == 1 {
            return BPF_RB_NO_WAKEUP;
        }

        let wakeup = read_volatile(addr_of!(wakeup_data_size));
        if wakeup == 0 {
            return 0;
        }

        let sz = bpf_ringbuf_query(&ringbuf, BPF_RB_AVAIL_DATA) as isize;
        if sz >= wakeup {
            BPF_RB_FORCE_WAKEUP
        } else {
            BPF_RB_NO_WAKEUP
        }
    }
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn bench_ringbuf(_ctx: *mut c_void) -> i32 {
    let mut i: i32;

    unsafe {
        if read_volatile(addr_of!(use_output)) == 0 {
            i = 0;
            while i < read_volatile(addr_of!(batch_cnt)) {
                let sample = bpf_ringbuf_reserve(&ringbuf, core::mem::size_of::<isize>() as u64, 0)
                    as *mut isize;
                if sample.is_null() {
                    sync_fetch_and_add(addr_of_mut!(dropped), 1);
                } else {
                    *sample = sample_val;
                    let flags = get_flags();
                    bpf_ringbuf_submit(sample as *mut c_void, flags as u64);
                    if read_volatile(addr_of!(bench_producer)) != 0 {
                        sync_fetch_and_add(addr_of_mut!(hits), 1);
                    }
                }
                i += 1;
            }
        } else {
            i = 0;
            while i < read_volatile(addr_of!(batch_cnt)) {
                let flags = get_flags();
                if bpf_ringbuf_output(
                    &ringbuf,
                    addr_of!(sample_val) as *const c_void,
                    core::mem::size_of::<isize>() as u64,
                    flags as u64,
                ) != 0
                {
                    sync_fetch_and_add(addr_of_mut!(dropped), 1);
                } else if read_volatile(addr_of!(bench_producer)) != 0 {
                    sync_fetch_and_add(addr_of_mut!(hits), 1);
                }
                i += 1;
            }
        }
    }
    0
}

bpf_object!("GPL");
