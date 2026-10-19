// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_hashmap_lookup.c
// (bpf-rs-core idiom). benchs/bench_bpf_hashmap_lookup.c sizes the key
// and the map from the command line, fills `key` (its first word is
// patched per element here) and the map, sets `nr_entries`/`nr_loops`,
// attaches the fentry program and reads the per-CPU `percpu_times` ring:
// each getpgid() looks every entry up nr_loops times through nested
// bpf_loop callbacks and records the elapsed nanoseconds in its CPU's
// next slot. The map is declared with its type only (the driver sets
// key/value sizes and max_entries). The C's .bss layout, with
// `percpu_times_index` and `percpu_times` 256-byte aligned, is kept
// (`// C_LAYOUT:`).
// C_LAYOUT: .bss

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut};

use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_loop, bpf_map_lookup_elem};
use bpf_rs_core::maps;
use bpf_rs_core::{bpf_map, bpf_object};

bpf_map! {
    hash_map_bench {
        r#type: *const [i32; maps::HASH],
    }
}

const NR_SLOTS: usize = 32;
const NR_CPUS: usize = 256;
const CPU_MASK: u32 = (NR_CPUS - 1) as u32;

/* configured by userspace */
#[no_mangle]
static mut nr_entries: u64 = 0;
#[no_mangle]
static mut nr_loops: u64 = 0;
#[no_mangle]
static mut key: [u32; NR_CPUS] = [0; NR_CPUS];

/* filled by us */
#[no_mangle]
static mut percpu_times_index: [u64; NR_CPUS] = [0; NR_CPUS];
#[no_mangle]
static mut percpu_times: [[u64; NR_SLOTS]; NR_CPUS] = [[0; NR_SLOTS]; NR_CPUS];

#[inline(always)]
fn patch_key(i: u32) {
    /* little endian: key[0] = i + 1; the rest of key is random and is
     * configured by userspace */
    unsafe { *addr_of_mut!(key).cast::<u32>() = i.wrapping_add(1) };
}

extern "C" fn lookup_callback(index: u64, _unused: *mut u32) -> i64 {
    patch_key(index as u32);
    if bpf_map_lookup_elem(&hash_map_bench, unsafe { &*addr_of!(key) }).is_null() {
        1
    } else {
        0
    }
}

extern "C" fn loop_lookup_callback(_index: u64, _unused: *mut u32) -> i64 {
    if bpf_loop(unsafe { nr_entries } as u32, lookup_callback, core::ptr::null_mut(), 0) != 0 {
        0
    } else {
        1
    }
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn benchmark(_ctx: *mut c_void) -> i32 {
    let cpu = bpf_get_smp_processor_id();

    unsafe {
        let times_index = (*addr_of!(percpu_times_index).cast::<u64>().add((cpu & CPU_MASK) as usize)
            % NR_SLOTS as u64) as u32;
        let start_time = bpf_ktime_get_ns();
        bpf_loop(nr_loops as u32, loop_lookup_callback, core::ptr::null_mut(), 0);
        *addr_of_mut!(percpu_times)
            .cast::<u64>()
            .add((cpu & CPU_MASK) as usize * NR_SLOTS + times_index as usize) =
            bpf_ktime_get_ns().wrapping_sub(start_time);
        *addr_of_mut!(percpu_times_index).cast::<u64>().add((cpu & CPU_MASK) as usize) += 1;
    }
    0
}

bpf_object!("GPL");
