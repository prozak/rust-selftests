// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_ringbuf_overwrite.c
// (bpf-rs-core idiom). prog_tests/ringbuf.c (ringbuf_overwrite_subtest)
// loads it as a light skeleton with the five LENs set at open time and
// calls getpgid(): on a BPF_F_RB_OVERWRITE ring buffer the program reserves
// records in the test's order, expects the third reservation to fail,
// submits the rest, fills the fifth with 0xdd and publishes the ring's
// positions through bpf_ringbuf_query. The LENs are `const volatile`
// .rodata: every read is a volatile load, like clang's.

use core::ffi::c_void;
use core::ptr::{addr_of, read_volatile};

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_ringbuf_discard, bpf_ringbuf_query, bpf_ringbuf_reserve,
    bpf_ringbuf_submit,
};
use bpf_rs_core::maps;
use bpf_rs_core::{bpf_map, bpf_object};

const BPF_RB_AVAIL_DATA: u64 = 0;
const BPF_RB_RING_SIZE: u64 = 1;
const BPF_RB_CONS_POS: u64 = 2;
const BPF_RB_PROD_POS: u64 = 3;
const BPF_RB_OVERWRITE_POS: u64 = 4;

bpf_map! {
    ringbuf {
        r#type: *const [i32; maps::RINGBUF],
        map_flags: *const [i32; 1 << 19], // BPF_F_RB_OVERWRITE
    }
}

#[no_mangle]
static mut pid: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static LEN1: usize = 0;
#[link_section = ".rodata"]
#[no_mangle]
static LEN2: usize = 0;
#[link_section = ".rodata"]
#[no_mangle]
static LEN3: usize = 0;
#[link_section = ".rodata"]
#[no_mangle]
static LEN4: usize = 0;
#[link_section = ".rodata"]
#[no_mangle]
static LEN5: usize = 0;

#[no_mangle]
static mut reserve1_fail: isize = 0;
#[no_mangle]
static mut reserve2_fail: isize = 0;
#[no_mangle]
static mut reserve3_fail: isize = 0;
#[no_mangle]
static mut reserve4_fail: isize = 0;
#[no_mangle]
static mut reserve5_fail: isize = 0;

#[no_mangle]
static mut avail_data: usize = 0;
#[no_mangle]
static mut ring_size: usize = 0;
#[no_mangle]
static mut cons_pos: usize = 0;
#[no_mangle]
static mut prod_pos: usize = 0;
#[no_mangle]
static mut over_pos: usize = 0;

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn test_overwrite_ringbuf(_ctx: *const c_void) -> i32 {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if cur_pid != unsafe { pid } {
        return 0;
    }

    unsafe {
        let rec1 = bpf_ringbuf_reserve(&ringbuf, read_volatile(addr_of!(LEN1)) as u64, 0) as *mut u8;
        if rec1.is_null() {
            reserve1_fail = 1;
            return 0;
        }

        let rec2 = bpf_ringbuf_reserve(&ringbuf, read_volatile(addr_of!(LEN2)) as u64, 0) as *mut u8;
        if rec2.is_null() {
            bpf_ringbuf_discard(rec1 as *mut c_void, 0);
            reserve2_fail = 1;
            return 0;
        }

        let rec3 = bpf_ringbuf_reserve(&ringbuf, read_volatile(addr_of!(LEN3)) as u64, 0) as *mut u8;
        /* expect failure */
        if rec3.is_null() {
            reserve3_fail = 1;
        } else {
            bpf_ringbuf_discard(rec1 as *mut c_void, 0);
            bpf_ringbuf_discard(rec2 as *mut c_void, 0);
            bpf_ringbuf_discard(rec3 as *mut c_void, 0);
            return 0;
        }

        let rec4 = bpf_ringbuf_reserve(&ringbuf, read_volatile(addr_of!(LEN4)) as u64, 0) as *mut u8;
        if rec4.is_null() {
            reserve4_fail = 1;
            bpf_ringbuf_discard(rec1 as *mut c_void, 0);
            bpf_ringbuf_discard(rec2 as *mut c_void, 0);
            return 0;
        }

        bpf_ringbuf_submit(rec1 as *mut c_void, 0);
        bpf_ringbuf_submit(rec2 as *mut c_void, 0);
        bpf_ringbuf_submit(rec4 as *mut c_void, 0);

        let rec5 = bpf_ringbuf_reserve(&ringbuf, read_volatile(addr_of!(LEN5)) as u64, 0) as *mut u8;
        if rec5.is_null() {
            reserve5_fail = 1;
            return 0;
        }

        let mut i: usize = 0;
        while i < read_volatile(addr_of!(LEN3)) {
            *rec5.add(i) = 0xdd;
            i += 1;
        }

        bpf_ringbuf_submit(rec5 as *mut c_void, 0);

        ring_size = bpf_ringbuf_query(&ringbuf, BPF_RB_RING_SIZE) as usize;
        avail_data = bpf_ringbuf_query(&ringbuf, BPF_RB_AVAIL_DATA) as usize;
        cons_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_CONS_POS) as usize;
        prod_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_PROD_POS) as usize;
        over_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_OVERWRITE_POS) as usize;
    }

    0
}

bpf_object!("GPL");
