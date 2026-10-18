// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_ringbuf_write.c
// (bpf-rs-core idiom). The test sets max_entries to 0x40000: the first
// 0x30000-byte reservation succeeds and the second must fail. `passed`
// and `discarded` are __sync_fetch_and_add'ed in C: plain `long` statics
// here, the atomic add at the access site (see test_ringbuf.rs).

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_ringbuf_discard, bpf_ringbuf_reserve, sync_fetch_and_add,
};
use bpf_rs_core::{bpf_map, bpf_object};

bpf_map! {
    ringbuf {
        r#type: *const [i32; 27], // BPF_MAP_TYPE_RINGBUF = 27
    }
}

/* inputs */
#[no_mangle]
static mut pid: i32 = 0;

/* outputs */
#[no_mangle]
static mut passed: isize = 0;
#[no_mangle]
static mut discarded: isize = 0;

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn test_ringbuf_write(_ctx: *const c_void) -> i32 {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if cur_pid != unsafe { pid } {
        return 0;
    }

    let sample1 = bpf_ringbuf_reserve(&ringbuf, 0x30000, 0);
    if sample1.is_null() {
        return 0;
    }
    /* first one can pass */
    let sample2 = bpf_ringbuf_reserve(&ringbuf, 0x30000, 0);
    if sample2.is_null() {
        bpf_ringbuf_discard(sample1, 0);
        sync_fetch_and_add(core::ptr::addr_of_mut!(discarded), 1);
        return 0;
    }
    /* second one must not */
    sync_fetch_and_add(core::ptr::addr_of_mut!(passed), 1);
    unsafe {
        let foo = (sample2 as *mut u8).add(4084) as *mut i32;
        *foo = 256;
    }
    bpf_ringbuf_discard(sample1, 0);
    bpf_ringbuf_discard(sample2, 0);
    0
}

bpf_object!("GPL");
