// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpftool_ringbuf.c
// (bpf-rs-core idiom). prog_tests/bpftool_ringbuf.c drives `bpftool map
// event_pipe` over the ring buffer and the perf buffer; `record` selects
// which sample `produce` emits. The three stack samples are built from
// immediates, as the C object does, so no memcpy from .rodata is needed.
// The C source names its license global `LICENSE`; the internalize
// keep-list comes from the C object's global symbols, so the crate macro's
// `_license` alone would be dropped and the object would load as non-GPL
// (bpf_perf_event_output is GPL-only). See bpf_flow.rs for `__license`.

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_perf_event_output, bpf_ringbuf_output};
use bpf_rs_core::{bpf_map, bpf_object};

const BPF_F_CURRENT_CPU: u64 = 0xffffffff;

bpf_map! {
    ringbuf {
        r#type: *const [i32; 27], // BPF_MAP_TYPE_RINGBUF
    }
}

bpf_map! {
    perfbuf {
        r#type: *const [i32; 4], // BPF_MAP_TYPE_PERF_EVENT_ARRAY
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
        max_entries: *const [i32; 1],
    }
}

/*
 * Include the u32 raw size in perf's 8-byte alignment to avoid padding.
 * Keep plain output large enough to flush stdio before the consumer exits.
 */
#[link_section = ".rodata"]
#[no_mangle]
static perf_payload: [u8; 4092] = {
    let mut p = [0u8; 4092];
    p[1] = 0xff;
    p
};

#[no_mangle]
static mut record: i32 = 0;
#[no_mangle]
static mut output_err: i32 = 0;

#[link_section = "socket"]
#[no_mangle]
extern "C" fn produce(skb: *mut __sk_buff) -> i32 {
    let first: [u8; 2] = [0x00, 0xff];
    let second: [u8; 5] = [1, 2, 3, 4, 5];
    let third: [u8; 17] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    let rec = unsafe { record };
    let err = if rec == 0 {
        bpf_ringbuf_output(&ringbuf, first.as_ptr() as *const c_void, 2, 0)
    } else if rec == 1 {
        bpf_ringbuf_output(&ringbuf, second.as_ptr() as *const c_void, 5, 0)
    } else if rec == 2 {
        bpf_ringbuf_output(&ringbuf, third.as_ptr() as *const c_void, 17, 0)
    } else {
        bpf_perf_event_output(
            skb as *const c_void,
            &perfbuf,
            BPF_F_CURRENT_CPU,
            &perf_payload,
            4092,
        )
    };
    unsafe { output_err = err as i32 };
    0
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
