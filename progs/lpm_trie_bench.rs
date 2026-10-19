// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

// Direct translation of tools/testing/selftests/bpf/progs/lpm_trie_bench.c
// (bpf-rs-core idiom). benchs/bench_lpm_trie_map.c fills the trie, sets
// `nr_entries`, `prefixlen`, `random` and `op`, runs the xdp program with
// bpf_prog_test_run and reads `hits` and `duration_ns`: run_bench runs
// NR_LOOPS of the selected operation through a bpf_loop callback and times
// it; the fentry/fexit pair on bpf_map_free_deferred times the freeing of
// the trie the driver names "trie_free_map". container_of(work, struct
// bpf_map, work), BPF_CORE_READ(map, map_type) and
// BPF_CORE_READ_STR_INTO(&name, map, name) are CO-RE field offsets of the
// `#[btf]` bpf_map view (the container_of subtracts the view's offset of
// `work` from the argument), the reads probe reads as in the C. `random`
// is the C's `bool` global, declared u8 and tested `== 1` as clang does
// (lesson 32). `cur_key`
// and `latency_free_start` are the C's statics (`#[export_name]`); the
// .bss order is the C's (`// C_LAYOUT:`). The bpf_printk format string is
// the C's `.rodata.str` static, the bpf_strncmp literal its `.rodata.str1.1`
// one. `barrier_var(blackbox)` and READ_ONCE(key.data) in `baseline` are
// black_box and a volatile read. The `% nr_entries` of the key generator is
// core::intrinsics::unchecked_rem: Rust's `%` adds a division-by-zero panic
// path (two panic subprograms) that the C's plain `w %= w` does not have
// (BPF defines the remainder by zero: the dividend is kept).
// C_LAYOUT: .bss

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::hint::black_box;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use bpf_rs_core::helpers::{
    bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_loop, bpf_map_delete_elem, bpf_map_lookup_elem,
    bpf_map_update_elem, bpf_probe_read_kernel, bpf_probe_read_kernel_str, bpf_strncmp,
    bpf_trace_printk, sync_fetch_and_add,
};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

const BPF_OBJ_NAME_LEN: usize = 16;
const MAX_ENTRIES: usize = 100000000;
const NR_LOOPS: u32 = 10000;

const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
const BPF_NOEXIST: u64 = 1;
const BPF_EXIST: u64 = 2;
const ENOENT: i32 = 2;

/* lpm_trie.h */
const LPM_OP_NOOP: u8 = 0;
const LPM_OP_BASELINE: u8 = 1;
const LPM_OP_LOOKUP: u8 = 2;
const LPM_OP_INSERT: u8 = 3;
const LPM_OP_UPDATE: u8 = 4;
const LPM_OP_DELETE: u8 = 5;
const LPM_BENCH_SUCCESS: i32 = 0;
const LPM_BENCH_REINIT_MAP: i32 = 1; /* Reset trie to initial state for current op */

#[allow(non_camel_case_types)]
#[repr(C)]
struct trie_key {
    prefixlen: u32,
    data: u32,
}

/* Filled by userspace. See fill_map() in bench_lpm_trie_map.c */
bpf_map! {
    trie_map {
        r#type: *const [i32; 11], // BPF_MAP_TYPE_LPM_TRIE
        key: *const trie_key,
        value: *const u32,
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        max_entries: *const [i32; MAX_ENTRIES],
    }
}

#[no_mangle]
static mut hits: isize = 0;
#[no_mangle]
static mut duration_ns: isize = 0;

/* Configured from userspace */
#[no_mangle]
static mut nr_entries: u32 = 0;
#[no_mangle]
static mut prefixlen: u32 = 0;
#[no_mangle]
static mut random: u8 = 0;
#[no_mangle]
static mut op: u8 = 0;

#[export_name = "latency_free_start"]
static mut latency_free_start: u64 = 0;

#[btf]
struct work_struct {
    _priv: [u8; 0],
}

#[btf]
struct bpf_map {
    map_type: u32,
    name: [u8; BPF_OBJ_NAME_LEN],
    work: work_struct,
}

#[link_section = ".rodata.str1.1"]
static TRIE_FREE_MAP: [u8; 14] = *b"trie_free_map\0";

#[link_section = "fentry/bpf_map_free_deferred"]
#[no_mangle]
extern "C" fn trie_free_entry(ctx: *const u64) -> i32 {
    let work = arg(ctx, 0) as *const u8;
    let mut name = MaybeUninit::<[u8; BPF_OBJ_NAME_LEN]>::uninit();
    let mut map_type: u32 = 0;

    unsafe {
        /* container_of(work, struct bpf_map, work) */
        let work_off = (&*(work as *const bpf_map)).work().field.as_ptr() as usize - work as usize;
        let map = work.sub(work_off) as *const bpf_map;

        bpf_probe_read_kernel(&mut map_type, 4, (&*map).map_type().as_ptr() as *const c_void);
        if map_type != BPF_MAP_TYPE_LPM_TRIE {
            return 0;
        }

        /*
         * Ideally we'd have access to the map ID but that's already
         * freed before we enter trie_free().
         */
        bpf_probe_read_kernel_str(
            name.as_mut_ptr() as *mut c_void,
            BPF_OBJ_NAME_LEN as u32,
            (&*map).name().as_ptr() as *const c_void,
        );
        if bpf_strncmp(name.as_ptr() as *const c_void, BPF_OBJ_NAME_LEN as u32, addr_of!(TRIE_FREE_MAP) as *const c_void) != 0 {
            return 0;
        }

        latency_free_start = bpf_ktime_get_ns();
    }
    0
}

#[link_section = "fexit/bpf_map_free_deferred"]
#[no_mangle]
extern "C" fn trie_free_exit(_ctx: *const u64) -> i32 {
    unsafe {
        if latency_free_start == 0 {
            return 0;
        }

        let val = bpf_ktime_get_ns().wrapping_sub(latency_free_start);
        latency_free_start = 0;
        sync_fetch_and_add(addr_of_mut!(duration_ns), val as isize);
        sync_fetch_and_add(addr_of_mut!(hits), 1);
    }
    0
}

#[export_name = "cur_key"]
static mut cur_key: u32 = 0;

#[inline(always)]
fn generate_key(key: &mut trie_key) {
    unsafe {
        key.prefixlen = prefixlen;

        if random == 1 {
            key.data = core::intrinsics::unchecked_rem(bpf_get_prandom_u32(), nr_entries);
        } else {
            key.data = core::intrinsics::unchecked_rem(cur_key, nr_entries);
            cur_key = cur_key.wrapping_add(1);
        }
    }
}

extern "C" fn noop(_index: u64, _unused: *mut u32) -> i64 {
    0
}

extern "C" fn baseline(_index: u64, _unused: *mut u32) -> i64 {
    let mut key = MaybeUninit::<trie_key>::uninit();
    let blackbox: u32 = 0;

    generate_key(unsafe { &mut *key.as_mut_ptr() });
    /* Avoid compiler optimizing out the modulo */
    let _blackbox = black_box(blackbox);
    let _ = unsafe { read_volatile(addr_of!((*key.as_ptr()).data)) };
    0
}

extern "C" fn lookup(_index: u64, retval: *mut i32) -> i64 {
    let mut key = MaybeUninit::<trie_key>::uninit();

    generate_key(unsafe { &mut *key.as_mut_ptr() });
    if bpf_map_lookup_elem(&trie_map, unsafe { &*key.as_ptr() }).is_null() {
        unsafe { *retval = -ENOENT };
        return 1;
    }
    0
}

extern "C" fn insert(_index: u64, retval: *mut i32) -> i64 {
    let mut key = MaybeUninit::<trie_key>::uninit();
    let val: u32 = 1;

    generate_key(unsafe { &mut *key.as_mut_ptr() });
    let err = bpf_map_update_elem(&trie_map, unsafe { &*key.as_ptr() }, &val, BPF_NOEXIST) as i32;
    if err != 0 {
        unsafe { *retval = err };
        return 1;
    }

    /* Is this the last entry? */
    if unsafe { (*key.as_ptr()).data } == unsafe { nr_entries }.wrapping_sub(1) {
        /* For atomicity concerns, see the comment in delete() */
        unsafe { *retval = LPM_BENCH_REINIT_MAP };
        return 1;
    }

    0
}

extern "C" fn update(_index: u64, retval: *mut i32) -> i64 {
    let mut key = MaybeUninit::<trie_key>::uninit();
    let val: u32 = 1;

    generate_key(unsafe { &mut *key.as_mut_ptr() });
    let err = bpf_map_update_elem(&trie_map, unsafe { &*key.as_ptr() }, &val, BPF_EXIST) as i32;
    if err != 0 {
        unsafe { *retval = err };
        return 1;
    }

    0
}

extern "C" fn delete(_index: u64, retval: *mut i32) -> i64 {
    let mut key = MaybeUninit::<trie_key>::uninit();

    generate_key(unsafe { &mut *key.as_mut_ptr() });
    let err = bpf_map_delete_elem(&trie_map, unsafe { &*key.as_ptr() }) as i32;
    if err != 0 {
        unsafe { *retval = err };
        return 1;
    }

    /* Do we need to refill the map? */
    if unsafe { (*key.as_ptr()).data } == unsafe { nr_entries }.wrapping_sub(1) {
        /*
         * Atomicity isn't required because DELETE only supports
         * one producer running concurrently. What we need is a
         * way to track how many entries have been deleted from
         * the trie between consecutive invocations of the BPF
         * prog because a single bpf_loop() call might not
         * delete all entries, e.g. when NR_LOOPS < nr_entries.
         */
        unsafe { *retval = LPM_BENCH_REINIT_MAP };
        return 1;
    }

    0
}

#[link_section = ".rodata.str"]
#[export_name = "____run_bench.____fmt"]
static run_bench____fmt: [u8; 29] = *b"invalid benchmark operation\n\0";

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn run_bench(_ctx: *mut c_void) -> i32 {
    let mut err: i32 = LPM_BENCH_SUCCESS;

    let start = bpf_ktime_get_ns();

    let loops: i64 = match unsafe { op } {
        LPM_OP_NOOP => bpf_loop(NR_LOOPS, noop, core::ptr::null_mut(), 0),
        LPM_OP_BASELINE => bpf_loop(NR_LOOPS, baseline, core::ptr::null_mut(), 0),
        LPM_OP_LOOKUP => bpf_loop(NR_LOOPS, lookup, &mut err, 0),
        LPM_OP_INSERT => bpf_loop(NR_LOOPS, insert, &mut err, 0),
        LPM_OP_UPDATE => bpf_loop(NR_LOOPS, update, &mut err, 0),
        LPM_OP_DELETE => bpf_loop(NR_LOOPS, delete, &mut err, 0),
        _ => {
            bpf_trace_printk(addr_of!(run_bench____fmt) as *const c_void, 29, 0, 0, 0);
            return -1;
        }
    };

    let delta = bpf_ktime_get_ns().wrapping_sub(start);
    sync_fetch_and_add(unsafe { addr_of_mut!(duration_ns) }, delta as isize);
    sync_fetch_and_add(unsafe { addr_of_mut!(hits) }, loops as isize);
    err
}

bpf_object!("GPL");
