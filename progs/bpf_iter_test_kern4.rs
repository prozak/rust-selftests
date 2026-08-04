#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_test_kern4.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_seq_write;
use btf_macros::btf;
use core::ffi::c_void;

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
static mut map1_id: u32 = 0;
#[no_mangle]
static mut map2_id: u32 = 0;
#[no_mangle]
static mut map1_accessed: u32 = 0;
#[no_mangle]
static mut map2_accessed: u32 = 0;
#[no_mangle]
static mut map1_seqnum: u64 = 0;
#[no_mangle]
static mut map2_seqnum1: u64 = 0;
#[no_mangle]
static mut map2_seqnum2: u64 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static print_len: u32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static ret1: u32 = 0;

#[link_section = "iter/bpf_map"]
#[no_mangle]
extern "C" fn dump_bpf_map(ctx: *const bpf_iter__bpf_map) -> i32 {
    let ctx = unsafe { &*ctx };
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;
    let map = ctx.map;

    if map.is_null() {
        return 0;
    }

    let map_ref = unsafe { &*map };
    let map_id = unsafe { *map_ref.id().as_ptr() };

    let id1 = unsafe { map1_id };
    let id2 = unsafe { map2_id };

    if map_id != id1 && map_id != id2 {
        return 0;
    }

    let seq_num = meta.seq_num;
    let mut ret: i32 = 0;

    if map_id == id1 {
        unsafe { map1_seqnum = seq_num };
        unsafe { map1_accessed += 1 };
    }

    if map_id == id2 {
        if unsafe { map2_accessed } == 0 {
            unsafe { map2_seqnum1 = seq_num };
            let ret1_v = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ret1)) };
            if ret1_v != 0 {
                ret = 1;
            }
        } else {
            unsafe { map2_seqnum2 = seq_num };
        }
        unsafe { map2_accessed += 1 };
    }

    let print_len_v = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(print_len)) };
    let mut i: i32 = 0;
    while i < print_len_v as i32 {
        bpf_seq_write(
            seq,
            &seq_num as *const u64 as *const c_void,
            core::mem::size_of::<u64>() as u32,
        );
        i += 1;
    }

    ret
}

bpf_object!("GPL");
