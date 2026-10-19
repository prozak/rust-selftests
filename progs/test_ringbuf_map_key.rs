// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_ringbuf_map_key.c
// (bpf-rs-core idiom). prog_tests/ringbuf.c (ringbuf_map_key_subtest)
// loads it as a light skeleton, sets `pid` and calls getpgid(): the
// reserved ringbuf sample (PTR_TO_MEM | MEM_ALLOC) is used as a hash map
// key, and a field of it as the update's value, before it is submitted.
// `__sink(lookup_val)` is `asm volatile("" : "+r"(x))`: black_box on the
// local keeps the lookup's result live as the C does (lesson 39/49).

use core::ffi::c_void;
use core::hint::black_box;

use bpf_rs_core::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_ringbuf_reserve, bpf_ringbuf_submit,
};
use bpf_rs_core::maps;
use bpf_rs_core::{bpf_map, bpf_object};

const BPF_ANY: u64 = 0;

#[allow(non_camel_case_types)]
#[repr(C)]
struct sample {
    pid: i32,
    seq: i32,
    value: isize,
    comm: [u8; 16],
}

bpf_map! {
    ringbuf {
        r#type: *const [i32; maps::RINGBUF],
    }
}

bpf_map! {
    hash_map {
        r#type: *const [i32; maps::HASH],
        max_entries: *const [i32; 1000],
        key: *const sample,
        value: *const i32,
    }
}

/* inputs */
#[no_mangle]
static mut pid: i32 = 0;

/* inner state */
#[no_mangle]
static mut seq: isize = 0;

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn test_ringbuf_mem_map_key(_ctx: *const c_void) -> i32 {
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
        bpf_get_current_comm((*sample).comm.as_mut_ptr() as *mut c_void, 16);
        seq += 1;
        (*sample).seq = seq as i32;
        (*sample).value = 42;

        /* test using 'sample' (PTR_TO_MEM | MEM_ALLOC) as map key arg
         */
        let lookup_val = bpf_map_lookup_elem(&hash_map, &*sample) as *mut i32;
        black_box(lookup_val);

        /*
         * Since bpf_map_lookup_elem above uses 'sample' as key, test using
         * sample field as value below
         */
        bpf_map_update_elem(&hash_map, &*sample, &(*sample).seq, BPF_ANY);

        bpf_ringbuf_submit(sample as *mut c_void, 0);
    }
    0
}

bpf_object!("GPL");
