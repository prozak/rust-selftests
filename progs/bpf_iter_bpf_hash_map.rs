#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_bpf_hash_map.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_delete_elem, bpf_map_update_elem, bpf_seq_printf};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__bpf_map_elem {
    meta: *mut bpf_iter_meta,
    map: *mut c_void,
    key: *mut c_void,
    value: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct key_t {
    a: i32,
    b: i32,
    c: i32,
}

#[btf]
struct bpf_map {
    id: u32,
}

#[link_section = ".maps"]
#[no_mangle]
static hashmap1: BpfMap<key_t, u64, { maps::HASH }, 3> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static hashmap2: BpfMap<u64, u64, { maps::HASH }, 3> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static hashmap3: BpfMap<key_t, u32, { maps::HASH }, 3> = BpfMap::new();

#[no_mangle]
static mut in_test_mode: bool = false;

#[no_mangle]
static mut key_sum_a: u32 = 0;
#[no_mangle]
static mut key_sum_b: u32 = 0;
#[no_mangle]
static mut key_sum_c: u32 = 0;
#[no_mangle]
static mut val_sum: u64 = 0;

#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
extern "C" fn dump_bpf_hash_map(ctx: *const bpf_iter__bpf_map_elem) -> i32 {
    let ctx = unsafe { &*ctx };
    let meta = unsafe { &*ctx.meta };
    let seq_num = meta.seq_num;
    let key = ctx.key as *mut key_t;
    let val = ctx.value as *mut u64;

    if unsafe { in_test_mode } {
        if key.is_null() || val.is_null() {
            return 0;
        }

        let tmp_key = key_t {
            a: unsafe { core::ptr::read_volatile(&(*key).a) },
            b: unsafe { core::ptr::read_volatile(&(*key).b) },
            c: unsafe { core::ptr::read_volatile(&(*key).c) },
        };
        let tmp_val: u64 = 0;
        let ret = bpf_map_update_elem(&hashmap1, &tmp_key, &tmp_val, 0);
        if ret != 0 {
            return 0;
        }
        let ret = bpf_map_delete_elem(&hashmap1, &tmp_key);
        if ret != 0 {
            return 0;
        }

        unsafe {
            key_sum_a += tmp_key.a as u32;
            key_sum_b += tmp_key.b as u32;
            key_sum_c += tmp_key.c as u32;
            val_sum += *val;
        }
        return 0;
    }

    if seq_num == 0 {
        static FMT0: [u8; 17] = *b"map dump starts\n\0";
        bpf_seq_printf(
            meta.seq,
            FMT0.as_ptr() as *const c_void,
            FMT0.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    if key.is_null() || val.is_null() {
        static FMT_END: [u8; 15] = *b"map dump ends\n\0";
        bpf_seq_printf(
            meta.seq,
            FMT_END.as_ptr() as *const c_void,
            FMT_END.len() as u32,
            core::ptr::null(),
            0,
        );
        return 0;
    }

    let map = ctx.map as *mut bpf_map;
    let map_id = unsafe { *(&*map).id().as_ptr() } as u64;
    let key_ref = unsafe { &*key };
    let key_a = key_ref.a as u64;
    let key_b = key_ref.b as u64;
    let key_c = key_ref.c as u64;
    let val_val = unsafe { *val };

    static FMT: [u8; 23] = *b"%d: (%x %d %x) (%llx)\n\0";
    let params: [u64; 5] = [map_id, key_a, key_b, key_c, val_val];
    bpf_seq_printf(
        meta.seq,
        FMT.as_ptr() as *const c_void,
        FMT.len() as u32,
        params.as_ptr() as *const c_void,
        core::mem::size_of_val(&params) as u32,
    );

    0
}

#[link_section = "iter.s/bpf_map_elem"]
#[no_mangle]
extern "C" fn sleepable_dummy_dump(ctx: *const bpf_iter__bpf_map_elem) -> i32 {
    let ctx = unsafe { &*ctx };
    let meta = unsafe { &*ctx.meta };

    if meta.seq_num == 0 {
        static FMT0: [u8; 17] = *b"map dump starts\n\0";
        bpf_seq_printf(
            meta.seq,
            FMT0.as_ptr() as *const c_void,
            FMT0.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    0
}

bpf_object!("GPL");
