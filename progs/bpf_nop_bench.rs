// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_nop_bench.c
// (bpf-rs-core idiom). benchs/bench_bpf_nop.c runs the syscall program
// with bpf_prog_test_run: BENCH_BPF_LOOP (bench_bpf_timing.bpf.h) times
// `batch_iters` empty iterations of a may_goto-guarded loop and records
// the elapsed nanoseconds in the per-CPU `timing_samples` when
// `timing_enabled` is set. `batch_iters` and `timing_enabled` are the C's
// `volatile` .bss globals (read_volatile); `can_loop` is bpf_may_goto.h's
// may_goto instruction, emitted as bytes with an `asm!` label as
// linked_list_peek.rs does. The .bss order is the C's (`// C_LAYOUT:`).
// C_LAYOUT: .bss

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_ktime_get_ns};

const BENCH_NR_SAMPLES: usize = 4096;
const BENCH_NR_CPUS: usize = 256;
const BENCH_CPU_MASK: u32 = (BENCH_NR_CPUS - 1) as u32;

#[no_mangle]
static mut timing_samples: [[u64; BENCH_NR_SAMPLES]; BENCH_NR_CPUS] = [[0; BENCH_NR_SAMPLES]; BENCH_NR_CPUS];
#[no_mangle]
static mut timing_idx: [u32; BENCH_NR_CPUS] = [0; BENCH_NR_CPUS];
#[no_mangle]
static mut batch_iters: u32 = 0;
#[no_mangle]
static mut timing_enabled: u32 = 0;

// bpf_may_goto.h's `can_loop`: the may_goto instruction, which the verifier
// lets the loop take only while it still has budget.
#[inline(always)]
unsafe fn can_loop() -> bool {
    let mut ret = true;
    core::arch::asm!(
        "1:",
        ".byte 0xe5",
        ".byte 0",
        ".long (({0} - 1b - 8) / 8) & 0xffff",
        ".short 0",
        label { ret = false; },
    );
    ret
}

#[inline(always)]
fn bench_record_sample(elapsed_ns: u64) {
    unsafe {
        if read_volatile(addr_of!(timing_enabled)) == 0 {
            return;
        }
        let cpu = bpf_get_smp_processor_id() & BENCH_CPU_MASK;
        let idx = *addr_of!(timing_idx).cast::<u32>().add(cpu as usize);
        if idx >= BENCH_NR_SAMPLES as u32 {
            return;
        }
        *addr_of_mut!(timing_samples).cast::<u64>().add(cpu as usize * BENCH_NR_SAMPLES + idx as usize) = elapsed_ns;
        *addr_of_mut!(timing_idx).cast::<u32>().add(cpu as usize) = idx + 1;
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn bench_nop(_ctx: *mut c_void) -> i32 {
    /* BENCH_BPF_LOOP(0, ({})) */
    let bench_start = bpf_ktime_get_ns();
    let mut bench_i: u32 = 0;

    while bench_i < unsafe { read_volatile(addr_of!(batch_iters)) } && unsafe { can_loop() } {
        bench_i += 1;
    }

    bench_record_sample(bpf_ktime_get_ns().wrapping_sub(bench_start));

    0
}

bpf_object!("GPL");
