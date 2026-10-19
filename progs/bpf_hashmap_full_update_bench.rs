// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/bpf_hashmap_full_update_bench.c
// (bpf-rs-core idiom). benchs/bench_bpf_hashmap_full_update.c sets
// `nr_loops`, fills the hash map, attaches the fentry program and reads
// the per-CPU `percpu_time`: each getpgid() updates one key of the full
// map nr_loops times through a bpf_loop callback and records the elapsed
// nanoseconds for its CPU. `percpu_time` is 256-byte aligned in the C
// (`// C_LAYOUT:` keeps the C's .bss layout: nr_loops at 0, percpu_time
// at 256).
// C_LAYOUT: .bss

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_loop, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::bpf_object;

const MAX_ENTRIES: usize = 1000;
const BPF_ANY: u64 = 0;

#[link_section = ".maps"]
#[no_mangle]
static hash_map_bench: BpfMap<u32, u64, { maps::HASH }, MAX_ENTRIES> = BpfMap::new();

#[no_mangle]
static mut percpu_time: [u64; 256] = [0; 256];
#[no_mangle]
static mut nr_loops: u64 = 0;

extern "C" fn loop_update_callback(_index: u64, key: *mut u32) -> i64 {
    let init_val: u64 = 1;

    bpf_map_update_elem(&hash_map_bench, unsafe { &*key }, &init_val, BPF_ANY);
    0
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn benchmark(_ctx: *mut c_void) -> i32 {
    let cpu = bpf_get_smp_processor_id();
    let mut key: u32 = cpu + MAX_ENTRIES as u32;
    let start_time = bpf_ktime_get_ns();

    bpf_loop(unsafe { nr_loops } as u32, loop_update_callback, &mut key, 0);

    unsafe {
        *addr_of_mut!(percpu_time).cast::<u64>().add((cpu & 255) as usize) =
            bpf_ktime_get_ns().wrapping_sub(start_time);
    }
    0
}

bpf_object!("GPL");
