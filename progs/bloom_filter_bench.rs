// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bloom_filter_bench.c
// (bpf-rs-core idiom). benchs/bench_bloom_filter_map.c sizes the three
// maps from the command line, fills `rand_vals` and the array map with
// random values, sets `value_size` and the two .rodata flags, attaches one
// fentry program per benchmark and sums the per-CPU `percpu_stats`:
// bloom_lookup/bloom_update walk the array map with a
// bpf_for_each_map_elem callback peeking at/pushing to the bloom filter,
// bloom_hashmap_lookup looks 1024 random values up in the hash map, with
// an optional bloom filter check first. The `const __u32` keys are the
// C's (unused in the code, which folds them, kept in .rodata); the
// `const volatile bool` flags are declared u8 (translint bool-global) and
// tested as clang tests them (`== 1`, lesson 32). `percpu_stats` is an
// array of 256-byte aligned structs; the C's .bss and .rodata layouts are
// kept (`// C_LAYOUT:`). `callback_ctx` has padding after `update`, which
// the C never zeroes either (both members are assigned, no `= {}`).
// translint: allow(padding)
// C_LAYOUT: .bss .rodata

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_for_each_map_elem, bpf_get_prandom_u32, bpf_get_smp_processor_id, bpf_map_lookup_elem,
    bpf_map_peek_elem, bpf_map_push_elem,
};

const ENOENT: i64 = 2;

#[no_mangle]
static mut rand_vals: [u8; 2500000] = [0; 2500000];
#[link_section = ".rodata"]
#[no_mangle]
static nr_rand_bytes: u32 = 2500000;

#[allow(non_camel_case_types)]
#[repr(C)]
struct array_map {
    r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY
    /* max entries and value_size will be set programmatically.
     * They are configurable from the userspace bench program.
     */
    key_size: *const [i32; 4],
}
unsafe impl Sync for array_map {}
#[link_section = ".maps"]
#[no_mangle]
static array_map: array_map = array_map { r#type: core::ptr::null(), key_size: core::ptr::null() };

#[allow(non_camel_case_types)]
#[repr(C)]
struct bloom_map {
    r#type: *const [i32; 30], // BPF_MAP_TYPE_BLOOM_FILTER
    /* max entries,  value_size, and # of hash functions will be set
     * programmatically. They are configurable from the userspace
     * bench program.
     */
    map_extra: *const [i32; 3],
}
unsafe impl Sync for bloom_map {}
#[link_section = ".maps"]
#[no_mangle]
static bloom_map: bloom_map = bloom_map { r#type: core::ptr::null(), map_extra: core::ptr::null() };

#[allow(non_camel_case_types)]
#[repr(C)]
struct hashmap {
    r#type: *const [i32; 1], // BPF_MAP_TYPE_HASH
    /* max entries, key_size, and value_size, will be set
     * programmatically. They are configurable from the userspace
     * bench program.
     */
}
unsafe impl Sync for hashmap {}
#[link_section = ".maps"]
#[no_mangle]
static hashmap: hashmap = hashmap { r#type: core::ptr::null() };

#[allow(non_camel_case_types)]
#[repr(C)]
struct callback_ctx {
    map: *mut c_void,
    update: bool,
}

/* Tracks the number of hits, drops, and false hits. Anonymous in the C
 * (`struct { ... } percpu_stats[256]`): the bench driver's skeleton
 * must embed the definition, not name an undefined `struct percpu_stats_t`.
 */
// BTF_ANON: percpu_stats_t
#[allow(non_camel_case_types)]
#[repr(C, align(256))]
struct percpu_stats_t {
    stats: [u32; 3],
}
#[no_mangle]
static mut percpu_stats: [percpu_stats_t; 256] = [const { percpu_stats_t { stats: [0; 3] } }; 256];

#[link_section = ".rodata"]
#[no_mangle]
static hit_key: u32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static drop_key: u32 = 1;
#[link_section = ".rodata"]
#[no_mangle]
static false_hit_key: u32 = 2;

#[no_mangle]
static mut value_size: u8 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static hashmap_use_bloom: u8 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static count_false_hits: u8 = 0;

#[no_mangle]
static mut error: i32 = 0;

#[inline(always)]
fn log_result(key: usize) {
    let cpu = bpf_get_smp_processor_id();
    unsafe {
        let stats = (*addr_of_mut!(percpu_stats).cast::<percpu_stats_t>().add((cpu & 255) as usize))
            .stats
            .as_mut_ptr()
            .add(key);
        *stats += 1;
    }
}

extern "C" fn bloom_callback(_map: *mut array_map, _key: *mut u32, val: *mut c_void, data: *mut callback_ctx) -> i64 {
    let data = unsafe { &*data };
    let err = if data.update {
        bpf_map_push_elem(data.map as *const c_void, unsafe { &*(val as *const u8) }, 0)
    } else {
        bpf_map_peek_elem(data.map as *const c_void, unsafe { &mut *(val as *mut u8) })
    };

    if err != 0 {
        unsafe { error |= 1 };
        return 1; /* stop the iteration */
    }

    log_result(0 /* hit_key */);
    0
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn bloom_lookup(_ctx: *mut c_void) -> i32 {
    let mut data = callback_ctx { map: addr_of!(bloom_map) as *mut c_void, update: false };

    bpf_for_each_map_elem(&array_map, bloom_callback, &mut data, 0);
    0
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn bloom_update(_ctx: *mut c_void) -> i32 {
    let mut data = callback_ctx { map: addr_of!(bloom_map) as *mut c_void, update: true };

    bpf_for_each_map_elem(&array_map, bloom_callback, &mut data, 0);
    0
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn bloom_hashmap_lookup(_ctx: *mut c_void) -> i32 {
    let mut index: u32 = bpf_get_prandom_u32();
    let bitmask: u32 = (1u64 << 21) as u32 - 1;
    let mut i: i32 = 0;

    while i < 1024 {
        index &= bitmask;
        unsafe {
            let val = addr_of_mut!(rand_vals).cast::<u8>().add(index as usize);
            if read_volatile(addr_of!(hashmap_use_bloom)) == 1 {
                let err = bpf_map_peek_elem(&bloom_map, &mut *val);
                if err != 0 {
                    if err != -ENOENT {
                        error |= 2;
                        return 0;
                    }
                    log_result(0 /* hit_key */);
                    i += 1;
                    index = index.wrapping_add(value_size as u32);
                    continue;
                }
            }

            let result = bpf_map_lookup_elem(&hashmap, &*val) as *mut u64;
            if !result.is_null() {
                log_result(0 /* hit_key */);
            } else {
                if read_volatile(addr_of!(hashmap_use_bloom)) == 1 && read_volatile(addr_of!(count_false_hits)) == 1 {
                    log_result(2 /* false_hit_key */);
                }
                log_result(1 /* drop_key */);
            }
            i += 1;
            index = index.wrapping_add(value_size as u32);
        }
    }

    0
}

bpf_object!("GPL");
