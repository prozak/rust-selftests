// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_ringbuf_n.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ringbuf_reserve, bpf_ringbuf_submit,
};
use bpf_rs_core::{bpf_map, bpf_object};

// The C struct has the same 4 padding bytes after `pid`; the sample is
// reserved from the ring buffer and never built from a literal, and the
// consumer reads the three fields, not the padding.
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct sample {
    pid: i32,
    value: isize,
    comm: [u8; 16],
}

bpf_map! {
    ringbuf {
        r#type: *const [i32; 27], // BPF_MAP_TYPE_RINGBUF = 27
    }
}

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut value: isize = 0;

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn test_ringbuf_n(_ctx: *const c_void) -> i32 {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if cur_pid != unsafe { pid } {
        return 0;
    }

    let sample = bpf_ringbuf_reserve(&ringbuf, core::mem::size_of::<sample>() as u64, 0)
        as *mut sample;
    if sample.is_null() {
        return 0;
    }

    unsafe {
        (*sample).pid = pid;
        (*sample).value = value;
        bpf_get_current_comm((*sample).comm.as_mut_ptr() as *mut c_void, 16);
        bpf_ringbuf_submit(sample as *mut c_void, 0);
    }

    0
}

bpf_object!("GPL");
