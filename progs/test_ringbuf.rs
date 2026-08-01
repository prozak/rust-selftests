#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_ringbuf.c,
// bpf-rs-core idiom.
//
// The globals total/discarded/dropped are updated with
// __sync_fetch_and_add in C; here they stay plain isize (BTF "long")
// statics (so the regenerated skeleton sees `long`, same as C) and the add
// goes through helpers::sync_fetch_and_add's atomic view of the same
// storage.

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ringbuf_discard, bpf_ringbuf_output,
    bpf_ringbuf_query, bpf_ringbuf_reserve, bpf_ringbuf_submit, sync_fetch_and_add,
};
use bpf_rs_core::{bpf_map, bpf_object};

#[allow(non_camel_case_types)]
#[repr(C)]
struct sample {
    pid: i32,
    seq: i32,
    value: i64,
    comm: [u8; 16],
}

bpf_map! {
    ringbuf {
        r#type: *const [i32; 27], // BPF_MAP_TYPE_RINGBUF = 27
    }
}

/* inputs */
#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut value: isize = 0;
#[no_mangle]
static mut flags: isize = 0;

/* outputs */
#[no_mangle]
static mut total: isize = 0;
#[no_mangle]
static mut discarded: isize = 0;
#[no_mangle]
static mut dropped: isize = 0;

#[no_mangle]
static mut avail_data: isize = 0;
#[no_mangle]
static mut ring_size: isize = 0;
#[no_mangle]
static mut cons_pos: isize = 0;
#[no_mangle]
static mut prod_pos: isize = 0;

/* inner state */
#[no_mangle]
static mut seq: isize = 0;

const BPF_RB_AVAIL_DATA: u64 = 0;
const BPF_RB_RING_SIZE: u64 = 1;
const BPF_RB_CONS_POS: u64 = 2;
const BPF_RB_PROD_POS: u64 = 3;

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn test_ringbuf(_ctx: *const c_void) -> i32 {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if cur_pid != unsafe { pid } {
        return 0;
    }

    let sample = bpf_ringbuf_reserve(&ringbuf, core::mem::size_of::<sample>() as u64, 0)
        as *mut sample;
    if sample.is_null() {
        sync_fetch_and_add(core::ptr::addr_of_mut!(dropped), 1);
        return 0;
    }

    unsafe {
        (*sample).pid = pid;
        bpf_get_current_comm((*sample).comm.as_mut_ptr() as *mut c_void, 16);
        (*sample).value = value as i64;

        (*sample).seq = seq as i32;
        seq += 1;
        sync_fetch_and_add(core::ptr::addr_of_mut!(total), 1);

        if (*sample).seq & 1 != 0 {
            /* copy from reserved sample to a new one... */
            bpf_ringbuf_output(
                &ringbuf,
                sample as *const c_void,
                core::mem::size_of::<sample>() as u64,
                flags as u64,
            );
            /* ...and then discard reserved sample */
            bpf_ringbuf_discard(sample as *mut c_void, flags as u64);
            sync_fetch_and_add(core::ptr::addr_of_mut!(discarded), 1);
        } else {
            bpf_ringbuf_submit(sample as *mut c_void, flags as u64);
        }

        avail_data = bpf_ringbuf_query(&ringbuf, BPF_RB_AVAIL_DATA) as isize;
        ring_size = bpf_ringbuf_query(&ringbuf, BPF_RB_RING_SIZE) as isize;
        cons_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_CONS_POS) as isize;
        prod_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_PROD_POS) as isize;
    }

    0
}

bpf_object!("GPL");
