// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/htab_mem_bench.c
// (bpf-rs-core idiom). benchs/bench_htab_mem.c sizes the map's value and
// max_entries from the command line, sets `nr_thread`, enables one of the
// four `?` tracepoint programs and reads `op_cnt`: each program runs a
// batch of OP_BATCH map updates or deletes from its CPU's key range
// through a bpf_loop callback. The map is declared with its type, key
// size and flags only, as the C does.

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut};

use bpf_rs_core::helpers::{
    bpf_get_smp_processor_id, bpf_loop, bpf_map_delete_elem, bpf_map_update_elem_ptr,
    sync_fetch_and_add,
};
use bpf_rs_core::{bpf_map, bpf_object};

const OP_BATCH: u32 = 64;
const BPF_NOEXIST: u64 = 1;

#[allow(non_camel_case_types)]
#[repr(C)]
struct update_ctx {
    from: u32,
    step: u32,
}

bpf_map! {
    htab {
        r#type: *const [i32; 1], // BPF_MAP_TYPE_HASH
        key_size: *const [i32; 4],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
    }
}

#[no_mangle]
static mut zeroed_value: [u8; 4096] = [0; 4096];

#[no_mangle]
static mut nr_thread: u32 = 0;
#[no_mangle]
static mut op_cnt: isize = 0;

#[inline(always)]
fn write_htab(_i: u32, ctx: *mut update_ctx, flags: u64) -> i64 {
    unsafe {
        bpf_map_update_elem_ptr(
            &htab,
            &*addr_of!((*ctx).from),
            addr_of!(zeroed_value) as *const c_void,
            flags,
        );
        (*ctx).from = (*ctx).from.wrapping_add((*ctx).step);
    }
    0
}

extern "C" fn overwrite_htab(i: u64, ctx: *mut update_ctx) -> i64 {
    write_htab(i as u32, ctx, 0)
}

extern "C" fn newwrite_htab(i: u64, ctx: *mut update_ctx) -> i64 {
    write_htab(i as u32, ctx, BPF_NOEXIST)
}

extern "C" fn del_htab(_i: u64, ctx: *mut update_ctx) -> i64 {
    unsafe {
        bpf_map_delete_elem(&htab, &*addr_of!((*ctx).from));
        (*ctx).from = (*ctx).from.wrapping_add((*ctx).step);
    }
    0
}

#[link_section = "?tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn overwrite(_ctx: *mut c_void) -> i32 {
    let mut update = update_ctx { from: bpf_get_smp_processor_id(), step: unsafe { nr_thread } };

    bpf_loop(OP_BATCH, overwrite_htab, &mut update, 0);
    sync_fetch_and_add(unsafe { addr_of_mut!(op_cnt) }, 1);
    0
}

#[link_section = "?tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn batch_add_batch_del(_ctx: *mut c_void) -> i32 {
    let mut update = update_ctx { from: bpf_get_smp_processor_id(), step: unsafe { nr_thread } };

    bpf_loop(OP_BATCH, overwrite_htab, &mut update, 0);
    update.from = bpf_get_smp_processor_id();
    bpf_loop(OP_BATCH, del_htab, &mut update, 0);
    sync_fetch_and_add(unsafe { addr_of_mut!(op_cnt) }, 2);
    0
}

#[link_section = "?tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn add_only(_ctx: *mut c_void) -> i32 {
    let mut update = update_ctx { from: bpf_get_smp_processor_id() / 2, step: unsafe { nr_thread } / 2 };

    bpf_loop(OP_BATCH, newwrite_htab, &mut update, 0);
    sync_fetch_and_add(unsafe { addr_of_mut!(op_cnt) }, 1);
    0
}

#[link_section = "?tp/syscalls/sys_enter_getppid"]
#[no_mangle]
extern "C" fn del_only(_ctx: *mut c_void) -> i32 {
    let mut update = update_ctx { from: bpf_get_smp_processor_id() / 2, step: unsafe { nr_thread } / 2 };

    bpf_loop(OP_BATCH, del_htab, &mut update, 0);
    sync_fetch_and_add(unsafe { addr_of_mut!(op_cnt) }, 1);
    0
}

bpf_object!("GPL");
