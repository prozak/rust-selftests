#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_test_kern2.c
// (which is bpf_iter_test_kern_common.h with START_CHAR == 'A')
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_seq_write;
use core::ffi::c_void;

const START_CHAR: u8 = b'A';

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__task {
    meta: *mut bpf_iter_meta,
    task: *mut c_void,
}

#[no_mangle]
static mut count: i32 = 0;

#[link_section = "iter/task"]
#[no_mangle]
extern "C" fn dump_task(ctx: *const bpf_iter__task) -> i32 {
    let ctx = unsafe { &*ctx };
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;

    if unsafe { count } < 4 {
        let c: u8 = START_CHAR.wrapping_add(unsafe { count } as u8);
        bpf_seq_write(seq, &c as *const u8 as *const c_void, core::mem::size_of::<u8>() as u32);
        unsafe { count += 1 };
    }

    0
}

bpf_object!("GPL");
