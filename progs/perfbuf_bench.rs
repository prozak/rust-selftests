// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/perfbuf_bench.c
// (bpf-rs-core idiom). benchs/bench_ringbufs.c (pb-libbpf, pb-custom)
// sets `batch_cnt` in .rodata at open time, attaches the fentry program
// and counts the samples its consumer receives against `dropped`: the
// program outputs `sample_val` batch_cnt times per getpgid() through the
// perf event array. `batch_cnt` is `const volatile`: re-read every
// iteration, as clang does. `dropped` is 128-byte aligned in the C
// (`// C_LAYOUT:` keeps the C's .bss layout).
// C_LAYOUT: .bss

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use bpf_rs_core::helpers::{bpf_perf_event_output, sync_fetch_and_add};
use bpf_rs_core::{bpf_map, bpf_object};

const BPF_F_CURRENT_CPU: u64 = 0xffffffff;

bpf_map! {
    perfbuf {
        r#type: *const [i32; 4], // BPF_MAP_TYPE_PERF_EVENT_ARRAY
        value_size: *const [i32; 4],
        key_size: *const [i32; 4],
    }
}

#[link_section = ".rodata"]
#[no_mangle]
static batch_cnt: i32 = 0;

#[no_mangle]
static mut sample_val: isize = 42;
#[no_mangle]
static mut dropped: isize = 0;

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn bench_perfbuf(ctx: *mut c_void) -> i32 {
    let mut i: i32 = 0;

    while i < unsafe { read_volatile(addr_of!(batch_cnt)) } {
        if bpf_perf_event_output(
            ctx,
            &perfbuf,
            BPF_F_CURRENT_CPU,
            unsafe { &*addr_of!(sample_val) },
            core::mem::size_of::<isize>() as u64,
        ) != 0
        {
            sync_fetch_and_add(unsafe { addr_of_mut!(dropped) }, 1);
        }
        i += 1;
    }
    0
}

bpf_object!("GPL");
