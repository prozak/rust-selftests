// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/map_percpu_stats.c
// (bpf-rs-core idiom). map_tests/map_percpu_stats.c (test_maps, which the
// gate does not run: #68) sets `target_id` and reads the bpf_map iterator's
// output: for the map with that id the program prints
// bpf_map_sum_elem_count(map) with BPF_SEQ_PRINTF. `map->id` is a direct
// read of the iterator's trusted map pointer through the `#[btf]` view
// (bpf_iter_bpf_map.rs); the kfunc takes the same pointer.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_seq_printf;
use btf_macros::btf;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__bpf_map {
    meta: *mut bpf_iter_meta,
    map: *mut bpf_map,
}

#[btf]
struct bpf_map {
    id: u32,
}

#[no_mangle]
static mut target_id: u32 = 0;

extern "C" {
    fn bpf_map_sum_elem_count(map: *const bpf_map) -> i64;
}

#[link_section = "iter/bpf_map"]
#[no_mangle]
extern "C" fn dump_bpf_map(ctx: *const bpf_iter__bpf_map) -> i32 {
    let ctx = unsafe { &*ctx };
    let seq = unsafe { (*ctx.meta).seq };
    let map = ctx.map;

    if !map.is_null() && unsafe { *(&*map).id().as_ptr() } == unsafe { target_id } {
        static FMT: [u8; 5] = *b"%lld\0";
        let params: [u64; 1] = [unsafe { bpf_map_sum_elem_count(map) } as u64];
        bpf_seq_printf(
            seq,
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            params.as_ptr() as *const c_void,
            core::mem::size_of_val(&params) as u32,
        );
    }
    0
}

bpf_object!("GPL");
